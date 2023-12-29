use crate::{ProxyEngine, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::TcpListener;
use tokio_native_tls::TlsAcceptor;
use tokio_native_tls::native_tls::{self, Identity};

pub struct TlsMitm {
    bind_addr: SocketAddr,
    server_id: Identity,
    client_id: Identity,
    file_dir: PathBuf,
}

impl TlsMitm {
    pub fn new(
        bind_addr: SocketAddr,
        server_id: Identity,
        client_id: Identity,
        file_dir: &Path,
    ) -> Self {
        let file_dir = file_dir.into();
        Self { bind_addr, server_id, client_id, file_dir }
    }

    pub async fn serve(&self) -> Result<()> {
        let acceptor = native_tls::TlsAcceptor::new(self.server_id.to_owned())?;
        let acceptor = TlsAcceptor::from(acceptor);

        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("Listening on {:?}", self.bind_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("Accepted {:?}", addr);

            let acceptor = acceptor.to_owned();

            let conn_addr = self.bind_addr.to_owned();
            let client_id = self.client_id.to_owned();
            let file_dir = self.file_dir.to_owned();

            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await?;
                ProxyEngine::new(stream, Some(conn_addr), Some(client_id), file_dir).run().await
            });
        }
    }
}
