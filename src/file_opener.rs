use crate::{DductError, Request, Result};
use lazy_static::lazy_static;
use nix::fcntl::{FlockArg, flock};
use regex::Regex;
use std::fs::create_dir_all;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};

pub struct FileOpener {
    pub file_dir: PathBuf,
}

impl FileOpener {
    pub fn new(file_dir: PathBuf) -> Self {
        Self { file_dir }
    }

    pub fn get_path(&self, req: &Request) -> PathBuf {
        let path = self.file_dir.join(req.uri().path().strip_prefix('/').unwrap());
        path
    }

    pub fn get_partial_path(&self, req: &Request, maybe_path: Option<PathBuf>) -> (PathBuf, PathBuf) {
        let path = maybe_path.or(Some(self.get_path(req))).unwrap();
        let dir = path.parent().unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        let tmp_name = format!("{}.{}", name, "dduct");
        let tmp_path = dir.join(tmp_name);
        (tmp_path, path)
    }

    pub fn is_cached(&self, req: &Request) -> bool {
        lazy_static! {
            static ref RE: Vec<Regex> = vec![
                Regex::new(r"^/v2/.*/blobs/sha256:\w+$").unwrap(), // docker
                Regex::new(r"^/.*\.(?:apk|deb|rpm)$").unwrap(),
                Regex::new(r"^/.*\.(?:7z|bz2|gz|tar|xz|zip|zst)$").unwrap(),
            ];
        }
        let path = req.uri().path();
        RE.iter().any(|re| re.is_match(path))
    }

    pub async fn open_ro(&self, req: &Request) -> Result<(File, u64)> {
        let path = self.get_path(req);
        if path.is_dir() {
            Err(DductError::NotAFile)
        } else {
            let file = OpenOptions::new()
                .read(true)
                .write(false)
                .open(path)
                .await?;
            let metadata = file.metadata().await?;
            Ok((file, metadata.len()))
        }
    }

    pub async fn open_partial_ro(&self, req: &Request) -> Result<(File, PathBuf, PathBuf)> {
        let (tmp_path, path) = self.get_partial_path(req, None);
        let tmp_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_path.as_path())
            .await?;
        Ok((tmp_file, tmp_path, path))
    }

    pub async fn open_partial_wo_or_ro(&self, req: &Request, maybe_path: Option<PathBuf>) -> Result<(File, PathBuf, PathBuf, bool)> {
        let (tmp_path, path) = self.get_partial_path(req, maybe_path);
        create_dir_all(tmp_path.parent().unwrap())?;

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
                return Ok((tmp_file, tmp_path, path, true))
            }
        }

        let tmp_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_path.as_path())
            .await?;

        return Ok((tmp_file, tmp_path, path, false))
    }
}
