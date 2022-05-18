use crate::{ProxyEngine, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::TcpListener;
use tokio_native_tls::native_tls::Identity;

pub struct HttpProxy {
    bind_addr: SocketAddr,
    conn_addr: SocketAddr,
    client_id: Identity,
    file_dir: PathBuf,
}

impl HttpProxy {
    pub fn new(
        bind_addr: SocketAddr,
        conn_addr: SocketAddr,
        client_id: Identity,
        file_dir: &Path,
    ) -> Self {
        let file_dir = file_dir.to_path_buf();
        Self { bind_addr, conn_addr, client_id, file_dir }
    }

    pub async fn serve(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        log::info!("Listening on {:?}", self.bind_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("Accepted {:?}", addr);

            let conn_addr = self.conn_addr.clone();
            let client_id = self.client_id.clone();
            let file_dir = self.file_dir.clone();

            tokio::spawn(async move {
                ProxyEngine::new(stream, Some(conn_addr), Some(client_id), file_dir).run().await
            });
        }
    }
}
