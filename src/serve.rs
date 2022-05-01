use crate::{HttpProxy, Result, TlsMitm};
use futures::future::{self};
use std::net::SocketAddr;
use std::path::Path;
use tokio_native_tls::native_tls::Identity;

pub async fn serve(
    tcp_bind_addr: SocketAddr,
    tls_bind_addr: SocketAddr,
    server_id: Identity,
    client_id: Identity,
    file_dir: &Path,
) -> Result<()> {
    log::info!("Files {:?}", file_dir);
    future::try_join(
        HttpProxy::new(
            tcp_bind_addr,
            tls_bind_addr,
            client_id.clone(),
            file_dir,
        ).serve(),
        TlsMitm::new(
            tls_bind_addr,
            server_id,
            client_id.clone(),
            file_dir,
        ).serve(),
    ).await?;
    Ok(())
}
