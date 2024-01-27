use crate::{FileOpener, ProxyEngine, Result, SslCerts, detect_ifaddrs};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_native_tls::TlsAcceptor;
use tokio_native_tls::native_tls::{self};

pub struct TlsMitm<'a> {
    bind_addr: SocketAddr,
    ssl_certs: &'a SslCerts,
    file_opener: &'a FileOpener,
}

impl<'a> TlsMitm<'a> {
    pub fn new(
        bind_addr: SocketAddr,
        ssl_certs: &'a SslCerts,
        file_opener: &'a FileOpener,
    ) -> Self {
        Self { bind_addr, ssl_certs, file_opener }
    }

    pub async fn serve(&self) -> Result<()> {
        let acceptor = native_tls::TlsAcceptor::new(self.ssl_certs.server_id()?)?;
        let acceptor = TlsAcceptor::from(acceptor);

        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("Listening on {:?}", self.bind_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("Accepted {:?}", addr);

            let acceptor = acceptor.to_owned();

            let conn_addr = self.bind_addr.to_owned();
            let client_id = self.ssl_certs.client_id()?.to_owned();
            let server_dns_sans = self.ssl_certs.server_dns_sans.to_owned();
            let server_ip_sans = self.ssl_certs.server_ip_sans.to_owned();
            let file_opener = self.file_opener.to_owned();
            let ifaddrs = detect_ifaddrs()?;

            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await?;
                ProxyEngine::new(
                    stream,
                    Some(conn_addr),
                    Some(client_id),
                    server_dns_sans,
                    server_ip_sans,
                    file_opener,
                    ifaddrs,
                ).run().await
            });
        }
    }
}
