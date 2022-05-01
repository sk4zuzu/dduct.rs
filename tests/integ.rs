use dduct::{HttpProxy, Result, SslCerts, TlsMitm, serve};
use futures::future;
use hex::{self};
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha1::{Digest, Sha1};
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

fn get_sha1(path: &Path) -> std::io::Result<Sha1> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha1::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hasher)
}

async fn download_file(proxy_url: &str, url: &str, maybe_path: Option<PathBuf>) -> Result<Child> {
    let mut command = Command::new("curl");
    command
        .arg("--silent")
        .arg("--fail")
        .arg("--proxy-insecure")
        .arg("--proxy").arg(proxy_url)
        .arg("--insecure")
        .arg(url);

    if let Some(path) = maybe_path {
        command.arg("--output").arg(path);
    } else {
        command.arg("--remote-name");
    }

    Ok(command.spawn()?)
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

    let string = random_string(64);
    for index in 1..=4 {
        let mut file = File::create(static_dir.path().join(index.to_string())).await?;
        for _ in 0..(16 * 1024) {
            file.write(string.as_bytes()).await?;
            file.write(b"\n").await?;
        }
    }

    let mut ssl_certs = SslCerts::new(cert_dir.path());
    ssl_certs.generate()?;

    let result = time::timeout(
        Duration::from_secs(30),
        future::try_join4(
            // Helper: serve static files over tcp..
            HttpProxy::new(
                ([0, 0, 0, 0], 8001).into(),
                ([127, 0, 0, 1], 4431).into(),
                ssl_certs.client_id()?.clone(),
                static_dir.path(),
            ).serve(),
            // Helper: serve static files over tls..
            TlsMitm::new(
                ([0, 0, 0, 0], 4432).into(),
                ssl_certs.server_id()?.clone(),
                ssl_certs.client_id()?.clone(),
                static_dir.path(),
            ).serve(),
            // Run full proxy..
            serve(
                ([0, 0, 0, 0], 8003).into(),
                ([127, 0, 0, 1], 4433).into(),
                ssl_certs.server_id()?.clone(),
                ssl_certs.client_id()?.clone(),
                file_dir.path(),
            ),
            // Tests: run some requests..
            async {
                sleep(Duration::from_secs(8)).await;

                download_file("http://127.0.0.1:8003", "http://127.0.0.1:8001/1", None).await.unwrap();
                download_file("http://127.0.0.1:8003", "http://127.0.0.1:8001/1", None).await.unwrap();

                download_file("http://127.0.0.1:8003", "https://127.0.0.1:4432/2", None).await.unwrap();
                download_file("http://127.0.0.1:8003", "https://127.0.0.1:4432/2", None).await.unwrap();

                download_file("https://127.0.0.1:4433", "http://127.0.0.1:8001/3", None).await.unwrap();
                download_file("https://127.0.0.1:4433", "http://127.0.0.1:8001/3", None).await.unwrap();

                download_file("https://127.0.0.1:4433", "https://127.0.0.1:4432/4", None).await.unwrap();
                download_file("https://127.0.0.1:4433", "https://127.0.0.1:4432/4", None).await.unwrap();

                Ok(())
            },
        ),
    ).await;
    log::debug!("{:?}", result);

    // Verify if source, cached and output files are all identical.
    let (dirs, names) = (
        [work_dir.path(), static_dir.path(), file_dir.path()].repeat(4),
        ["1", "2", "3", "4"].repeat(3),
    );
    let files = dirs.iter()
        .zip(names.iter())
        .map(|(dir, name)| dir.join(name));
    let cksums: Vec<_> = files
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

    let string = random_string(64);
    for index in 1..=1 {
        let mut file = File::create(static_dir.path().join(index.to_string())).await?;
        for _ in 0..(256 * 1024) {
            file.write(string.as_bytes()).await?;
            file.write(b"\n").await?;
        }
    }

    let mut ssl_certs = SslCerts::new(cert_dir.path());
    ssl_certs.generate()?;

    let result = time::timeout(
        Duration::from_secs(30),
        future::try_join5(
            // Helper: serve static files over tls..
            TlsMitm::new(
                ([0, 0, 0, 0], 4434).into(),
                ssl_certs.server_id()?.clone(),
                ssl_certs.client_id()?.clone(),
                static_dir.path(),
            ).serve(),
            // Run full proxy..
            serve(
                ([0, 0, 0, 0], 8005).into(),
                ([127, 0, 0, 1], 4435).into(),
                ssl_certs.server_id()?.clone(),
                ssl_certs.client_id()?.clone(),
                file_dir.path(),
            ),
            // Tests: run some requests..
            async {
                sleep(Duration::from_secs(8)).await;
                download_file("https://127.0.0.1:4435", "https://127.0.0.1:4434/1", Some("A".into())).await.unwrap();
                Ok(())
            },
            async {
                sleep(Duration::from_secs(8)).await;
                download_file("https://127.0.0.1:4435", "https://127.0.0.1:4434/1", Some("B".into())).await.unwrap();
                Ok(())
            },
            async {
                sleep(Duration::from_secs(8)).await;
                download_file("https://127.0.0.1:4435", "https://127.0.0.1:4434/1", Some("C".into())).await.unwrap();
                Ok(())
            },
        ),
    ).await;
    log::debug!("{:?}", result);

    // Verify if source, cached and output files are all identical.
    let files = vec![
        static_dir.path().join("1"),
        file_dir.path().join("1"),
        work_dir.path().join("A"),
        work_dir.path().join("B"),
        work_dir.path().join("C"),
    ];
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
