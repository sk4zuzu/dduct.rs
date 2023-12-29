use futures::{future::Future, ready};
use sha1::{Digest, Sha1};
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

const BUFFER_SIZE: usize = 8*1024;

struct DoubleCopy<'a, R, W1, W2>
where
    R: ?Sized,
    W1: ?Sized,
    W2: ?Sized,
{
    reader: &'a mut R,
    hasher: Sha1,
    read_done: bool,
    writer1: &'a mut W1,
    writer2: &'a mut W2,
    pos1: usize,
    pos2: usize,
    cap: usize,
    buf: ReadBuf<'a>,
}

pub async fn double_copy<'a, R, W1, W2>(
    reader: &'a mut R,
    writer1: &'a mut W1,
    writer2: &'a mut W2,
) -> io::Result<Sha1>
where
    R: AsyncRead + Unpin + ?Sized,
    W1: AsyncWrite + Unpin + ?Sized,
    W2: AsyncWrite + Unpin + ?Sized,
{
    DoubleCopy {
        reader,
        hasher: Sha1::new(),
        read_done: false,
        writer1,
        writer2,
        pos1: 0,
        pos2: 0,
        cap: 0,
        buf: ReadBuf::uninit(&mut [MaybeUninit::<u8>::uninit(); BUFFER_SIZE]),
    }.await
}

impl<R, W1, W2> Future for DoubleCopy<'_, R, W1, W2>
where
    R: AsyncRead + Unpin + ?Sized,
    W1: AsyncWrite + Unpin + ?Sized,
    W2: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<Sha1>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            if me.pos1 == me.cap && me.pos2 == me.cap && !me.read_done {
                me.buf.clear();
                match ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut me.buf)) {
                    Err(e) => return Err(e).into(),
                    Ok(_) => {
                        if me.buf.filled().len() == 0 {
                            me.read_done = true;
                        } else {
                            me.hasher.update(me.buf.filled());
                            me.pos1 = 0;
                            me.pos2 = 0;
                            me.cap = me.buf.filled().len();
                        }
                    },
                }
            }

            while me.pos1 < me.cap || me.pos2 < me.cap {
                if me.pos1 < me.cap {
                    match ready!(Pin::new(&mut *me.writer1).poll_write(cx, &me.buf.filled()[me.pos1..me.cap])) {
                        Err(e) => return Err(e).into(),
                        Ok(n) => {
                            if n == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "write zero bytes into writer",
                                )).into();
                            } else {
                                me.pos1 += n;
                            }
                        },
                    }
                }
                if me.pos2 < me.cap {
                    match ready!(Pin::new(&mut *me.writer2).poll_write(cx, &me.buf.filled()[me.pos2..me.cap])) {
                        Err(e) => return Err(e).into(),
                        Ok(n) => {
                            if n == 0 {
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "write zero bytes into writer",
                                )).into();
                            } else {
                                me.pos2 += n;
                            }
                        },
                    }
                }
            }

            if me.pos1 == me.cap && me.pos2 == me.cap && me.read_done {
                match ready!(Pin::new(&mut *me.writer1).poll_flush(cx)) {
                    Err(e) => return Err(e).into(),
                    Ok(_) => (),
                }
                match ready!(Pin::new(&mut *me.writer2).poll_flush(cx)) {
                    Err(e) => return Err(e).into(),
                    Ok(_) => (),
                }
                return Ok(me.hasher.to_owned()).into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use std::path::Path;
    use tempdir::TempDir;
    use tokio::fs::{self};

    fn setup() {
        env_logger::try_init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug")).ok();
    }

    fn get_sha1(path: &Path) -> std::io::Result<Sha1> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha1::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok(hasher)
    }

    #[tokio::test]
    async fn test_double_copy() -> io::Result<()> {
        setup();

        let dir = TempDir::new("dduct")?;

        let mut rng = rand::thread_rng();
        let something: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(3*BUFFER_SIZE/2)
            .collect();

        let path_a = dir.path().join("a");
        let path_b = dir.path().join("b");
        let path_c = dir.path().join("c");

        fs::write(&path_a, &something).await?;
        log::debug!("Write {:?} <<< {:?}", &path_a, &something);

        let mut file_a = fs::File::open(&path_a).await?;
        let mut file_b = fs::File::create(&path_b).await?;
        let mut file_c = fs::File::create(&path_c).await?;

        let hash_a = double_copy(&mut file_a, &mut file_b, &mut file_c).await?.finalize();
        let hash_b = get_sha1(&path_b)?.finalize();
        let hash_c = get_sha1(&path_c)?.finalize();

        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a, hash_c);
        Ok(())
    }
}
