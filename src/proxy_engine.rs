use crate::{DductError, HttpParser, HttpRenderer, Request, Response, Result, double_copy};
use futures::future::{self};
use http::header::{self};
use http::method::Method;
use http::status::StatusCode;
use http::uri::{Scheme, Uri};
use nix::fcntl::{FlockArg, flock};
use nix::unistd::close;
use std::fs::create_dir_all;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::fs::{File, OpenOptions, rename};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, TlsStream};
use tokio_native_tls::native_tls::{self, Identity};

pub struct ProxyEngine<S> {
    pub stream: S,
    pub maybe_raw_fd: Option<RawFd>,
    pub maybe_mitm_addr: Option<SocketAddr>,
    pub maybe_client_id: Option<Identity>,
    pub file_dir: PathBuf,
}

impl<S> ProxyEngine<S> where S: AsyncReadExt + AsyncWriteExt + Unpin {
    pub fn new(
        stream: S,
        maybe_raw_fd: Option<RawFd>,
        maybe_mitm_addr: Option<SocketAddr>,
        maybe_client_id: Option<Identity>,
        file_dir: PathBuf,
    ) -> Self {
        Self { stream, maybe_raw_fd, maybe_mitm_addr, maybe_client_id, file_dir }
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

    async fn send_response(&mut self, resp: &Response) -> Result<()> {
        let payload = HttpRenderer::render_response(&resp);
        self.send_payload(&payload).await
    }

    async fn send_empty_response(&mut self, status: StatusCode) -> Result<()> {
        let resp = http::Response::builder()
            .status(status)
            .header(header::CONNECTION, "close")
            .body(None)
            .unwrap();
        self.send_response(&resp).await
    }

    async fn open_file_ro(&self, req: &Request) -> Result<(File, u64)> {
        let path = self.file_dir
            .join(req.uri().path().strip_prefix('/').unwrap());
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .await?;
        let metadata = file.metadata().await?;
        Ok((file, metadata.len()))
    }

    async fn open_partial_file_wo_or_ro(&self, req: &Request) -> Result<(File, PathBuf, bool)> {
        let path = self.file_dir
            .join(req.uri().path().strip_prefix('/').unwrap());

        let dir = path.parent().unwrap();
        create_dir_all(dir)?;
        let name = path.file_name().unwrap().to_str().unwrap();
        let tmp_name = format!("{}.{}", name, "dduct");
        let tmp_path = dir.join(tmp_name);

        // Try to open write-only (with lock).
        if !tmp_path.exists() {
            let tmp_file = OpenOptions::new()
                .read(false)
                .write(true)
                .truncate(true)
                .create(true)
                .open(tmp_path.as_path())
                .await?;
            if let Ok(()) = flock(tmp_file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
                return Ok((tmp_file, tmp_path, true))
            }
        }

        let tmp_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_path.as_path())
            .await?;

        return Ok((tmp_file, tmp_path, false))
    }

    async fn copy_from<A>(&mut self, stream_a: &mut A) -> Result<()>
    where
        A: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        io::copy(stream_a, &mut self.stream).await?;
        Ok(())
    }

    async fn copy_to<A>(&mut self, stream_a: &mut A) -> Result<()>
    where
        A: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        io::copy(&mut self.stream, stream_a).await?;
        Ok(())
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

    async fn tcp_connect(&mut self, req: &mut Request) -> Result<(TcpStream, RawFd)> {
        log::debug!("tcp_connect(): {:?}", req);

        let host = req.uri().host().unwrap();
        let port = req.uri().port().map(|p| p.as_u16()).or(Some(80)).unwrap();

        let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let raw_fd = stream.as_raw_fd();

        Ok((stream, raw_fd))
    }

    async fn tls_connect(&mut self, req: &mut Request) -> Result<(TlsStream<TcpStream>, RawFd)> {
        log::debug!("tls_connect(): {:?}", req);

        let uri: Uri = req.headers()
            .get(header::HOST)
            .unwrap()
            .to_str()
            .map_err(|_| DductError::BadRequest)?
            .parse()
            .map_err(|_| DductError::BadRequest)?;
        let host = uri.host().unwrap();
        let port = uri.port().map(|p| p.as_u16()).or(Some(443)).unwrap();

        let connector = native_tls::TlsConnector::builder()
            .identity(self.maybe_client_id.as_ref().unwrap().clone())
            .danger_accept_invalid_certs(true)
            .build()?;
        let connector = TlsConnector::from(connector);

        let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        let raw_fd = stream.as_raw_fd();

        let stream = connector.connect(host, stream).await?;

        Ok((stream, raw_fd))
    }

    async fn _proxy_request<P>(&mut self, req: &mut Request, maybe_file: Option<File>, peer_stream: &mut P) -> Result<()>
    where
        P: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let path = req.uri().path();
        *req.uri_mut() = path.parse()
            .map_err(|_| DductError::BadRequest)?;

        // Make sure server closes the connection.
        req.headers_mut()
            .remove(header::CONNECTION);
        req.headers_mut()
            .insert(header::CONNECTION, "close".parse().unwrap());

        let mut peer_engine = ProxyEngine::new(peer_stream, None, None, None, self.file_dir.clone());
        peer_engine.send_request(req).await?;

        if let Some(resp) = peer_engine.recv_response().await? {
            self.send_response(&resp).await?;

            if resp.status() == StatusCode::OK {
                if let Some(ref body) = resp.body() {
                    if let Some(mut file) = maybe_file {
                        file.write_all(body).await?;
                        peer_engine.dcopy_to(&mut self.stream, &mut file).await?;
                    } else {
                        peer_engine.copy_to(&mut self.stream).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn proxy_request(&mut self, req: &mut Request, maybe_file: Option<File>) -> Result<()> {
        if req.uri().scheme() == Some(&Scheme::HTTP) {
            let (mut peer_stream, peer_raw_fd) = self.tcp_connect(req).await?;
            let result = self._proxy_request(req, maybe_file, &mut peer_stream).await;
            peer_stream.shutdown().await.ok();
            close(peer_raw_fd).ok();
            result
        } else {
            // Assume HTTPS..
            let (mut peer_stream, peer_raw_fd) = self.tls_connect(req).await?;
            let result = self._proxy_request(req, maybe_file, &mut peer_stream).await;
            peer_stream.shutdown().await.ok();
            close(peer_raw_fd).ok();
            result
        }
    }

    async fn handle_connect(&mut self, req: &Request) -> Result<()> {
        log::debug!("handle_connect(): {:?}", req);
        let mitm_addr = self.maybe_mitm_addr.unwrap();
        let mut peer_stream = TcpStream::connect(mitm_addr).await?;
        let resp = http::Response::builder()
            .status(StatusCode::OK)
            .body(Some("".into()))
            .unwrap();
        self.send_response(&resp).await?;
        self.glue_with(&mut peer_stream).await?;
        Ok(())
    }

    async fn handle_head(&mut self, req: &mut Request) -> Result<()> {
        log::debug!("handle_head(): {:?}", req);
        match self.open_file_ro(req).await {
            Ok((_, length)) => {
                let resp = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, length)
                    .header(header::CONNECTION, "close")
                    .body(None)
                    .unwrap();
                self.send_response(&resp).await
            },
            Err(DductError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                self.proxy_request(req, None).await
            },
            Err(e) => Err(e),
        }
    }

    async fn handle_get(&mut self, req: &mut Request) -> Result<()> {
        log::debug!("handle_get(): {:?}", req);
        match self.open_file_ro(req).await {
            Ok((mut file, length)) => {
                let resp = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, length)
                    .header(header::CONNECTION, "close")
                    .body(Some("".into()))
                    .unwrap();
                self.send_response(&resp).await?;
                self.copy_from(&mut file).await?;
                Ok(())
            },
            Err(DductError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                let path = self.file_dir
                    .join(req.uri().path().strip_prefix('/').unwrap());

                match self.open_partial_file_wo_or_ro(req).await {
                    Ok((mut file, tmp_path, write_only)) => {
                        if write_only {
                            self.proxy_request(req, Some(file)).await?;
                            rename(tmp_path.as_path(), path.as_path()).await?;
                            Ok(())
                        } else {
                            let resp = http::Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONNECTION, "close")
                                .body(Some("".into()))
                                .unwrap();
                            self.send_response(&resp).await?;
                            while { self.copy_from(&mut file).await?; tmp_path.exists() } {}
                            Ok(())
                        }
                    },
                    Err(e) => Err(e),
                }
            },
            Err(e) => Err(e),
        }
    }

    async fn handle_any(&mut self, req: &Request) -> Result<()> {
        log::debug!("handle_any(): {:?}", req);
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

    async fn dispatch_error(&mut self, error: &DductError) -> Result<()> {
        let status = match error {
            DductError::BadRequest => StatusCode::BAD_REQUEST,
            DductError::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        self.send_empty_response(status).await
    }

    pub async fn run(&mut self) -> Result<()> {
        if let Err(ref err) = self.dispatch_request().await {
            log::error!("{:?}", err);
            self.dispatch_error(err).await.ok();
        }
        self.stream.shutdown().await.ok();
        if let Some(raw_fd) = self.maybe_raw_fd {
            close(raw_fd).ok();
        }
        Ok(())
    }
}
