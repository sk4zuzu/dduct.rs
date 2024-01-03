use crate::{FileOpener, ProxyEngine, Result, SslCerts};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub struct HttpProxy<'a> {
    bind_addr: SocketAddr,
    conn_addr: SocketAddr,
    ssl_certs: &'a SslCerts,
    file_opener: &'a FileOpener,
}

impl<'a> HttpProxy<'a> {
    pub fn new(
        bind_addr: SocketAddr,
        conn_addr: SocketAddr,
        ssl_certs: &'a SslCerts,
        file_opener: &'a FileOpener,
    ) -> Self {
        Self { bind_addr, conn_addr, ssl_certs, file_opener }
    }

    pub async fn serve(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("Listening on {:?}", self.bind_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("Accepted {:?}", addr);

            let conn_addr = self.conn_addr.to_owned();
            let client_id = self.ssl_certs.client_id()?.to_owned();
            let server_dns_sans = self.ssl_certs.server_dns_sans.to_owned();
            let server_ip_sans = self.ssl_certs.server_ip_sans.to_owned();
            let file_opener = self.file_opener.to_owned();

            tokio::spawn(async move {
                ProxyEngine::new(
                    stream,
                    Some(conn_addr),
                    Some(client_id),
                    server_dns_sans,
                    server_ip_sans,
                    file_opener,
                ).run().await
            });
        }
    }
}
