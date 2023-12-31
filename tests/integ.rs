use dduct::{DductCfg, FileOpener, HttpProxy, Result, SslCerts, TlsMitm, serve};
use futures::future;
use hex::{self};
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha1::{Digest, Sha1};
use std::default::Default;
use std::env::set_current_dir;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempdir::TempDir;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::time::{self, sleep};

fn setup() {
    env_logger::try_init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug")).ok();
}

fn random_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let string: String = std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(len)
        .collect();
    string
}

async fn generate_files(static_dir: &Path, number_of_files: usize, number_of_blocks: usize) -> Result<()> {
    let string = random_string(64);
    for index in 1..=number_of_files {
        let basename = format!("{}.gz", index.to_string());
        let mut file = File::create(static_dir.join(basename)).await?;
        for _ in 0..(16 * number_of_blocks) {
            file.write(string.as_bytes()).await?;
            file.write(b"\n").await?;
        }
    }
    Ok(())
}

fn get_sha1(path: &Path) -> std::io::Result<Sha1> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha1::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hasher)
}

async fn download_file(maybe_proxy_url: Option<&str>, url: &str, maybe_path: Option<PathBuf>) -> Result<Child> {
    log::info!("download_file(): {:?}", url);

    let mut command = Command::new("curl");
    command
        .arg("--silent")
        .arg("--fail")
        .arg("--proxy-insecure")
        .arg("--insecure")
        .arg(url);

    if let Some(proxy_url) = maybe_proxy_url {
        command.arg("--proxy").arg(proxy_url);
    }

    if let Some(path) = maybe_path {
        command.arg("--output").arg(path);
    } else {
        command.arg("--remote-name");
    }

    Ok(command.spawn()?)
}

fn get_files(dirs: Vec<&Path>, files: Vec<&str>) -> Vec<PathBuf> {
    let (dirs, names) = (
        dirs.repeat(files.len()),
        files.repeat(dirs.len()),
    );
    let files = dirs.iter()
        .zip(names.iter())
        .map(|(dir, name)| dir.join(name))
        .collect();
    files
}

fn verify_cksums(files: Vec<PathBuf>) -> Result<()> {
    let cksums: Vec<_> = files.iter()
        .map(|path| { log::debug!("path = {:?}", path); path })
        .map(|path| get_sha1(path.as_path()).unwrap().finalize())
        .map(|cksum| { log::debug!("cksum = {:?}", hex::encode(cksum)); cksum })
        .collect();
    for cksum in &cksums {
        assert_eq!(&cksums[0], cksum);
    }
    Ok(())
}

#[tokio::test]
async fn test_static() -> Result<()> {
    setup();

    let work_dir = TempDir::new("dduct")?;
    log::info!("Work {:?}", work_dir.path());

    let static_dir = TempDir::new("dduct")?;
    log::info!("Static {:?}", static_dir.path());

    let cert_dir = TempDir::new("dduct")?;
    log::info!("Certs {:?}", cert_dir.path());

    set_current_dir(work_dir.path())?;

    generate_files(static_dir.path(), 4, 1024).await?;

    let cfg = DductCfg {
        cert_dir: cert_dir.path().into(),
        ..Default::default()
    };

    let mut ssl_certs = SslCerts::new(&cfg);
    ssl_certs.generate()?;

    let result = time::timeout(
        Duration::from_secs(30),
        future::try_join3(
            // Helper: serve static files over tcp..
            HttpProxy::new(
                ([0, 0, 0, 0], 8001).into(),
                ([127, 0, 0, 1], 4431).into(),
                ssl_certs.client_id()?.to_owned(),
                FileOpener::new(static_dir.path(), None),
            ).serve(),
            // Helper: serve static files over tls..
            TlsMitm::new(
                ([0, 0, 0, 0], 4432).into(),
                ssl_certs.server_id()?.to_owned(),
                ssl_certs.client_id()?.to_owned(),
                FileOpener::new(static_dir.path(), None),
            ).serve(),
            // Tests: run some requests..
            async {
                sleep(Duration::from_secs(4)).await;

                download_file(None, "http://127.0.0.1:8001/1.gz", None).await.unwrap();

                download_file(None, "https://127.0.0.1:4432/2.gz", None).await.unwrap();

                download_file(None, "http://127.0.0.1:8001/3.gz", None).await.unwrap();

                download_file(None, "https://127.0.0.1:4432/4.gz", None).await.unwrap();

                Ok(())
            },
        ),
    ).await;
    log::debug!("{:?}", result);

    verify_cksums(get_files(
        vec![work_dir.path(), static_dir.path()],
        vec!["1.gz", "2.gz", "3.gz", "4.gz"],
    ))?;

    Ok(())
}

#[tokio::test]
async fn test_serial() -> Result<()> {
    setup();

    let work_dir = TempDir::new("dduct")?;
    log::info!("Work {:?}", work_dir.path());

    let static_dir = TempDir::new("dduct")?;
    log::info!("Static {:?}", static_dir.path());

    let cert_dir = TempDir::new("dduct")?;
    log::info!("Certs {:?}", cert_dir.path());

    let file_dir = TempDir::new("dduct")?;
    log::info!("Files {:?}", file_dir.path());

    set_current_dir(work_dir.path())?;

    generate_files(static_dir.path(), 4, 1024).await?;

    let cfg = DductCfg {
        cert_dir: cert_dir.path().into(),
        file_dir: file_dir.path().into(),
        tcp_bind: ([0, 0, 0, 0], 8003).into(),
        tls_bind: ([127, 0, 0, 1], 4433).into(),
        ..Default::default()
    };

    let mut ssl_certs = SslCerts::new(&cfg);
    ssl_certs.generate()?;

    let result = time::timeout(
        Duration::from_secs(30),
        future::try_join4(
            // Helper: serve static files over tcp..
            HttpProxy::new(
                ([0, 0, 0, 0], 8001).into(),
                ([127, 0, 0, 1], 4431).into(),
                ssl_certs.client_id()?.to_owned(),
                FileOpener::new(static_dir.path(), None),
            ).serve(),
            // Helper: serve static files over tls..
            TlsMitm::new(
                ([0, 0, 0, 0], 4432).into(),
                ssl_certs.server_id()?.to_owned(),
                ssl_certs.client_id()?.to_owned(),
                FileOpener::new(static_dir.path(), None),
            ).serve(),
            // Run full proxy..
            serve(&cfg, &ssl_certs),
            // Tests: run some requests..
            async {
                sleep(Duration::from_secs(8)).await;

                download_file(Some("http://127.0.0.1:8003"), "http://127.0.0.1:8001/1.gz", None).await.unwrap();
                download_file(Some("http://127.0.0.1:8003"), "http://127.0.0.1:8001/1.gz", None).await.unwrap();

                download_file(Some("http://127.0.0.1:8003"), "https://127.0.0.1:4432/2.gz", None).await.unwrap();
                download_file(Some("http://127.0.0.1:8003"), "https://127.0.0.1:4432/2.gz", None).await.unwrap();

                download_file(Some("https://127.0.0.1:4433"), "http://127.0.0.1:8001/3.gz", None).await.unwrap();
                download_file(Some("https://127.0.0.1:4433"), "http://127.0.0.1:8001/3.gz", None).await.unwrap();

                download_file(Some("https://127.0.0.1:4433"), "https://127.0.0.1:4432/4.gz", None).await.unwrap();
                download_file(Some("https://127.0.0.1:4433"), "https://127.0.0.1:4432/4.gz", None).await.unwrap();

                Ok(())
            },
        ),
    ).await;
    log::debug!("{:?}", result);

    verify_cksums(get_files(
        vec![work_dir.path(), static_dir.path(), file_dir.path()],
        vec!["1.gz", "2.gz", "3.gz", "4.gz"],
    ))?;

    Ok(())
}

#[tokio::test]
async fn test_parallel() -> Result<()> {
    setup();

    let work_dir = TempDir::new("dduct")?;
    log::info!("Work {:?}", work_dir.path());

    let static_dir = TempDir::new("dduct")?;
    log::info!("Static {:?}", static_dir.path());

    let cert_dir = TempDir::new("dduct")?;
    log::info!("Certs {:?}", cert_dir.path());

    let file_dir = TempDir::new("dduct")?;
    log::info!("Files {:?}", file_dir.path());

    set_current_dir(work_dir.path())?;

    generate_files(static_dir.path(), 1, 16 * 1024).await?;

    let cfg = DductCfg {
        cert_dir: cert_dir.path().into(),
        file_dir: file_dir.path().into(),
        tcp_bind: ([0, 0, 0, 0], 8005).into(),
        tls_bind: ([127, 0, 0, 1], 4435).into(),
        ..Default::default()
    };

    let mut ssl_certs = SslCerts::new(&cfg);
    ssl_certs.generate()?;

    let result = time::timeout(
        Duration::from_secs(45),
        future::try_join5(
            // Helper: serve static files over tls..
            TlsMitm::new(
                ([0, 0, 0, 0], 4434).into(),
                ssl_certs.server_id()?.to_owned(),
                ssl_certs.client_id()?.to_owned(),
                FileOpener::new(static_dir.path(), None),
            ).serve(),
            // Run full proxy..
            serve(&cfg, &ssl_certs),
            // Tests: run some requests..
            async {
                sleep(Duration::from_secs(8)).await;
                download_file(Some("https://127.0.0.1:4435"), "https://127.0.0.1:4434/1.gz", Some("A".into())).await.unwrap();
                Ok(())
            },
            async {
                sleep(Duration::from_secs(8)).await;
                download_file(Some("https://127.0.0.1:4435"), "https://127.0.0.1:4434/1.gz", Some("B".into())).await.unwrap();
                Ok(())
            },
            async {
                sleep(Duration::from_secs(8)).await;
                download_file(Some("https://127.0.0.1:4435"), "https://127.0.0.1:4434/1.gz", Some("C".into())).await.unwrap();
                Ok(())
            },
        ),
    ).await;
    log::debug!("{:?}", result);

    verify_cksums(vec![
        static_dir.path().join("1.gz"),
        file_dir.path().join("1.gz"),
        work_dir.path().join("A"),
        work_dir.path().join("B"),
        work_dir.path().join("C"),
    ])?;

    Ok(())
}
