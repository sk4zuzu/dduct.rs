use crate::{DductError, FileOpener, HttpParser, HttpRenderer, Request, Response, Result, double_copy, resolve_addr};
use futures::future::{self};
use http::header::{self};
use http::method::Method;
use http::status::StatusCode;
use http::uri::{Scheme, Uri};
use std::collections::HashSet;
use std::iter::Iterator;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::fs::{File, remove_file, rename};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, TlsStream};
use tokio_native_tls::native_tls::{self, Identity};

pub struct ProxyEngine<S> {
    pub stream: S,
    pub closed: bool,
    pub maybe_mitm_addr: Option<SocketAddr>,
    pub maybe_client_id: Option<Identity>,
    pub cached_sans: HashSet<String>,
    pub file_opener: FileOpener,
    pub ifaddrs: HashSet<IpAddr>,
}

impl<S> ProxyEngine<S> where S: AsyncReadExt + AsyncWriteExt + Unpin {
    pub fn new(
        stream: S,
        maybe_mitm_addr: Option<SocketAddr>,
        maybe_client_id: Option<Identity>,
        server_dns_sans: Vec<String>,
        server_ip_sans: Vec<String>,
        file_opener: FileOpener,
        ifaddrs: HashSet<IpAddr>,
    ) -> Self {
        let closed = false;
        let cached_sans = server_dns_sans.iter().cloned()
            .map(|s| s.strip_prefix("*").map(|s| s.into()).or(Some(s.to_owned())).unwrap())
            .chain(server_ip_sans.iter().cloned())
            .collect();
        Self { stream, closed, maybe_mitm_addr, maybe_client_id, cached_sans, file_opener, ifaddrs }
    }

    async fn recv_request(&mut self) -> Result<Option<Request>> {
        let mut parser = HttpParser::new(&mut self.stream);
        parser.parse_request().await
    }

    async fn recv_response(&mut self) -> Result<Option<Response>> {
        let mut parser = HttpParser::new(&mut self.stream);
        parser.parse_response().await
    }

    async fn send_payload(&mut self, payload: &Vec<u8>) -> Result<()> {
        let mut start = 0;
        loop {
            let slice = &payload[start..];
            let n = self.stream.write(slice).await?;
            if n == slice.len() {
                break Ok(());
            } else {
                start += n;
            }
        }
    }

    async fn send_request(&mut self, req: &Request) -> Result<()> {
        let payload = HttpRenderer::render_request(&req);
        self.send_payload(&payload).await
    }

    async fn send_response(&mut self, rsp: &Response) -> Result<()> {
        let payload = HttpRenderer::render_response(&rsp);
        self.send_payload(&payload).await
    }

    async fn send_empty_response(&mut self, status: StatusCode) -> Result<()> {
        let rsp = http::Response::builder()
            .status(status)
            .header(header::CONNECTION, "close")
            .body(None)
            .unwrap();
        self.send_response(&rsp).await
    }

    async fn send_file(
        &mut self,
        file: &mut File,
        maybe_length: Option<u64>,
    ) -> Result<()> {
        let mut build = http::Response::builder();
        build = build.status(StatusCode::OK);
        build = build.header(header::CONNECTION, "close");
        if let Some(length) = maybe_length { build = build.header(header::CONTENT_LENGTH, length); }
        let rsp = build.body(Some("".into())).unwrap();
        self.send_response(&rsp).await?;
        self.copy_from(file).await?;
        Ok(())
    }

    async fn send_partial_file(
        &mut self,
        file: &mut File,
        tmp_path: &Path,
        maybe_length: Option<u64>,
    ) -> Result<()> {
        let rsp = http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONNECTION, "close")
            .body(Some("".into()))
            .unwrap();
        self.send_response(&rsp).await?;
        if let Some(length) = maybe_length {
            let mut done: u64 = 0;
            loop {
                let n = self.copy_from(file).await?;
                done += n;
                if done >= length {
                    break;
                }
                if n == 0 && !tmp_path.exists() {
                    return Err(DductError::Incomplete);
                }
            }
        } else {
            loop {
                let n = self.copy_from(file).await?;
                if n == 0 && !tmp_path.exists() {
                    return Err(DductError::Incomplete);
                }
            }
        }
        Ok(())
    }

    async fn copy_from<A>(&mut self, stream_a: &mut A) -> Result<u64>
    where
        A: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        Ok(io::copy(stream_a, &mut self.stream).await?)
    }

    async fn copy_to<A>(&mut self, stream_a: &mut A) -> Result<u64>
    where
        A: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        Ok(io::copy(&mut self.stream, stream_a).await?)
    }

    async fn dcopy_to<A, B>(&mut self, stream_a: &mut A, stream_b: &mut B) -> Result<()>
    where
        A: AsyncReadExt + AsyncWriteExt + Unpin,
        B: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        double_copy(&mut self.stream, stream_a, stream_b).await?;
        Ok(())
    }

    async fn glue_with<A>(&mut self, stream_a: &mut A) -> Result<()>
    where
        A: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (mut s1_ro, mut s1_wo) = io::split(&mut self.stream);
        let (mut s2_ro, mut s2_wo) = io::split(stream_a);
        future::try_join(
            io::copy(&mut s1_ro, &mut s2_wo),
            io::copy(&mut s2_ro, &mut s1_wo),
        ).await?;
        Ok(())
    }

    async fn tcp_connect(&mut self, req: &mut Request) -> Result<TcpStream> {
        log::debug!("tcp_connect(): {:?} {:?} {:?}", req.method(), req.uri(), req.headers());

        let (addr, _) = resolve_addr(req).await?;

        let stream = TcpStream::connect(addr).await?;

        return Ok(stream);
    }

    async fn tls_connect(&mut self, req: &mut Request) -> Result<TlsStream<TcpStream>> {
        log::debug!("tls_connect(): REQ {:?} {:?} {:?}", req.method(), req.uri(), req.headers());

        let (addr, domain) = resolve_addr(req).await?;

        let connector = native_tls::TlsConnector::builder()
            .identity(self.maybe_client_id.as_ref().unwrap().to_owned())
            .danger_accept_invalid_certs(true)
            .build()?;
        let connector = TlsConnector::from(connector);

        let stream = TcpStream::connect(addr).await?;
        let stream = connector.connect(domain.as_str(), stream).await?;

        return Ok(stream);
    }

    async fn _proxy_request<P>(&mut self, req: &mut Request,
                               cached: bool, maybe_path: Option<PathBuf>,
                               peer_engine: &mut ProxyEngine<P>) -> Result<()>
    where
        P: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // Make sure server closes the connection.
        req.headers_mut().remove(header::CONNECTION);
        req.headers_mut().insert(header::CONNECTION, "close".parse().unwrap());

        log::debug!("proxy_request(): REQ {:?} {:?} {:?}", req.method(), req.uri(), req.headers());

        peer_engine.send_request(req).await?;

        if let Some(rsp) = peer_engine.recv_response().await? {
            log::debug!("proxy_request(): RSP {:?} {:?}", rsp.status(), rsp.headers());

            let maybe_length: Option<u64> = rsp.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok().and_then(|s| s.parse().ok()));

            match rsp.status() {
                StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED => {
                    self.send_response(&rsp).await?;
                    peer_engine.copy_to(&mut self.stream).await?;
                    Ok(())
                },
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {
                    let referer = format!("https://{}{}",
                        req.headers().get(header::HOST).unwrap().to_str().unwrap(),
                        req.uri().path(),
                    );
                    let location = rsp.headers().get(header::LOCATION).unwrap();
                    let uri: Uri = location.to_str().unwrap().parse().unwrap();
                    *req.uri_mut() = uri.to_owned();
                    req.headers_mut().remove(header::AUTHORIZATION);
                    req.headers_mut().remove(header::HOST);
                    req.headers_mut().insert(header::HOST, uri.host().unwrap().parse().unwrap());
                    req.headers_mut().insert(header::REFERER, referer.parse().unwrap());
                    Err(DductError::Redirected)
                },
                StatusCode::OK if cached => match self.file_opener.open_ro(req).await {
                    Ok((mut file, length)) if maybe_length == Some(length) => {
                        peer_engine.shutdown().await.ok();
                        self.send_file(&mut file, Some(length)).await
                    },
                    _ => match self.file_opener.open_partial_wo_or_ro(req, maybe_path).await {
                        Ok((mut file, tmp_path, path, write_only)) => {
                            if write_only {
                                let copy_data = async {
                                    if let Some(ref body) = rsp.body() { file.write_all(body).await?; }
                                    self.send_response(&rsp).await?;
                                    peer_engine.dcopy_to(&mut self.stream, &mut file).await?;
                                    Ok::<(), DductError>(())
                                };
                                match copy_data.await {
                                    Ok(()) => {
                                        rename(tmp_path.as_path(), path.as_path()).await?; // replace
                                        Ok(())
                                    },
                                    Err(e) => {
                                        remove_file(tmp_path.as_path()).await?; // cleanup
                                        Err(e)
                                    },
                                }
                            } else {
                                peer_engine.shutdown().await.ok();
                                self.send_partial_file(&mut file, tmp_path.as_path(), maybe_length).await
                            }
                        },
                        Err(e) => Err(e),
                    }
                },
                _ => {
                    self.send_response(&rsp).await?;
                    peer_engine.copy_to(&mut self.stream).await?;
                    Ok(())
                }
            }
        } else {
            Err(DductError::InternalServerError)
        }
    }

    async fn proxy_request(&mut self, req: &mut Request, cached: bool) -> Result<()> {
        loop {
            if req.uri().scheme() == Some(&Scheme::HTTP) {
                let peer_stream = self.tcp_connect(req).await?;
                let mut peer_engine = ProxyEngine::new(
                    peer_stream,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    FileOpener::new(self.file_opener.file_dir.as_path(), None),
                    HashSet::new(),
                );
                let result = self._proxy_request(
                    req,
                    cached,
                    Some(self.file_opener.get_path(req)),
                    &mut peer_engine,
                ).await;
                peer_engine.shutdown().await.ok();
                if let Err(DductError::Redirected) = result { continue; }
                return result;
            } else {
                let peer_stream = self.tls_connect(req).await?;
                let mut peer_engine = ProxyEngine::new(
                    peer_stream,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    FileOpener::new(self.file_opener.file_dir.as_path(), None),
                    HashSet::new(),
                );
                let result = self._proxy_request(
                    req,
                    cached,
                    Some(self.file_opener.get_path(req)),
                    &mut peer_engine,
                ).await;
                peer_engine.shutdown().await.ok();
                if let Err(DductError::Redirected) = result { continue; }
                return result;
            }
        }
    }

    async fn handle_connect(&mut self, req: &Request) -> Result<()> {
        log::debug!("handle_connect(): REQ {:?} {:?} {:?}", req.method(), req.uri(), req.headers());
        let host = req.uri().host().unwrap();
        let host_matches = self.cached_sans.iter().any(|h|
            if host.len() == h.len() {
                host == h
            } else {
                host.ends_with(h)
            }
        );
        let mut peer_stream = if host_matches {
            let mitm_addr = self.maybe_mitm_addr.unwrap();
            TcpStream::connect(mitm_addr).await?
        } else {
            let (addr, _) = resolve_addr(req).await?;
            TcpStream::connect(addr).await?
        };
        let rsp = http::Response::builder()
            .status(StatusCode::OK)
            .body(Some("".into()))
            .unwrap();
        self.send_response(&rsp).await?;
        self.glue_with(&mut peer_stream).await?;
        Ok(())
    }

    async fn handle_head(&mut self, req: &mut Request) -> Result<()> {
        log::debug!("handle_head(): REQ {:?} {:?} {:?}", req.method(), req.uri(), req.headers());
        self.proxy_request(req, false).await
    }

    async fn handle_get(&mut self, req: &mut Request) -> Result<()> {
        log::debug!("handle_get(): REQ {:?} {:?} {:?}", req.method(), req.uri(), req.headers());
        if self.file_opener.is_cached(req) {
            self.proxy_request(req, true).await
        } else {
            match self.file_opener.open_ro(req).await {
                // Handle static content.
                Ok((mut file, length)) => {
                    self.send_file(&mut file, Some(length)).await
                },
                Err(_) => {
                    if self.ifaddrs.contains(&resolve_addr(req).await?.0.ip()) {
                        Err(DductError::LoopDetected)
                    } else {
                        self.proxy_request(req, false).await
                    }
                },
            }
        }
    }

    async fn handle_any(&mut self, req: &Request) -> Result<()> {
        log::debug!("handle_any(): REQ {:?} {:?} {:?}", req.method(), req.uri(), req.headers());
        self.send_empty_response(StatusCode::NOT_IMPLEMENTED).await
    }

    async fn dispatch_request(&mut self) -> Result<()> {
        if let Some(mut req) = self.recv_request().await? {
            match *req.method() {
                Method::CONNECT => self.handle_connect(&mut req).await?,
                Method::HEAD => self.handle_head(&mut req).await?,
                Method::GET => self.handle_get(&mut req).await?,
                _ => self.handle_any(&mut req).await?,
            }
        }
        Ok(())
    }

    async fn dispatch_error(&mut self, e: &DductError) -> Result<()> {
        let status = match e {
            DductError::BadRequest => StatusCode::BAD_REQUEST,
            DductError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            DductError::LoopDetected => StatusCode::LOOP_DETECTED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        self.send_empty_response(status).await
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if !self.closed {
            self.stream.shutdown().await.ok();
            self.closed = true;
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        if let Err(ref e) = self.dispatch_request().await {
            log::error!("{:?}", e);
            self.dispatch_error(e).await.ok();
        }
        self.shutdown().await.ok();
        Ok(())
    }
}
