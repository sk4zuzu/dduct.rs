use crate::{DductCfg, HttpProxy, Result, SslCerts, TlsMitm};
use futures::future::{self};

pub async fn serve(cfg: &DductCfg, ssl_certs: &SslCerts) -> Result<()> {
    log::info!("Files {:?}", cfg.file_dir.as_path());

    future::try_join(
        HttpProxy::new(
            cfg.tcp_bind,
            cfg.tls_bind,
            ssl_certs.client_id()?.to_owned(),
            cfg.file_dir.as_path(),
        ).serve(),
        TlsMitm::new(
            cfg.tls_bind,
            ssl_certs.server_id()?.to_owned(),
            ssl_certs.client_id()?.to_owned(),
            cfg.file_dir.as_path(),
        ).serve(),
    ).await?;

    Ok(())
}
