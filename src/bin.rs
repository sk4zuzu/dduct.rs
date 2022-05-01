use dduct::{Result, SslCerts, serve};
use std::env::current_exe;
use std::fs::create_dir_all;
use std::path::PathBuf;

fn ensure_dirs() -> Result<(PathBuf, PathBuf)> {
    let parent_dir = current_exe()?
        .parent()
        .unwrap()
        .to_path_buf();

    let file_dir = parent_dir.join("files");
    if !file_dir.exists() {
        create_dir_all(file_dir.as_path())?;
    }

    let cert_dir = parent_dir.join("certs");
    if !cert_dir.exists() {
        create_dir_all(cert_dir.as_path())?;
    }

    Ok((file_dir, cert_dir))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"));

    let (file_dir, cert_dir) = ensure_dirs()?;

    let mut ssl_certs = SslCerts::new(cert_dir.as_path());
    ssl_certs.generate()?;

    serve(
        ([0, 0, 0, 0], 8000).into(),
        ([0, 0, 0, 0], 4430).into(),
        ssl_certs.server_id()?,
        ssl_certs.client_id()?,
        file_dir.as_path(),
    ).await
}
