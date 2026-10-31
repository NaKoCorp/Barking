//! Frames: 4-byte big-endian length, then the postcard body.

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum size of a request (body only).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Maximum size of a response (body only).
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too large ({len} bytes, maximum {max})")]
    TooLarge { len: usize, max: usize },
    #[error("stream cleanly closed before any frame")]
    Closed,
    #[error("truncated frame")]
    Truncated,
    #[error("invalid frame body")]
    Malformed,
    #[error("I/O error: {0}")]
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, FrameError>;

fn io_err(e: std::io::Error) -> FrameError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        FrameError::Truncated
    } else {
        FrameError::Io(e)
    }
}

/// Encodes a complete frame (header included); rejects a body larger
/// than `max`.
pub fn encode<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(value).map_err(|_| FrameError::Malformed)?;
    if body.len() > max {
        return Err(FrameError::TooLarge {
            len: body.len(),
            max,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        len: body.len(),
        max,
    })?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Writes a frame; rejects a body larger than `max`. Returns the number
/// of bytes written (header included).
pub async fn write<T: Serialize>(
    w: &mut (impl AsyncWrite + Unpin),
    value: &T,
    max: usize,
) -> Result<usize> {
    let bytes = encode(value, max)?;
    w.write_all(&bytes).await.map_err(io_err)?;
    Ok(bytes.len())
}

/// Reads a frame. The announced length is checked before any allocation.
pub async fn read<T: DeserializeOwned>(r: &mut (impl AsyncRead + Unpin), max: usize) -> Result<T> {
    Ok(read_counted(r, max).await?.0)
}

/// Like `read`, and also returns the number of bytes read (header included).
pub async fn read_counted<T: DeserializeOwned>(
    r: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> Result<(T, usize)> {
    let mut head = [0u8; 4];
    // EOF before the first byte: clean close; afterwards: truncated.
    let mut got = 0;
    while got < head.len() {
        let n = r.read(&mut head[got..]).await.map_err(io_err)?;
        if n == 0 {
            return Err(if got == 0 {
                FrameError::Closed
            } else {
                FrameError::Truncated
            });
        }
        got += n;
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    // The buffer grows as bytes are received: a header alone does not reserve
    // `len` bytes (no amplification by a peer that sends nothing).
    let mut body = Vec::new();
    let n = r
        .take(len as u64)
        .read_to_end(&mut body)
        .await
        .map_err(io_err)?;
    if n < len {
        return Err(FrameError::Truncated);
    }
    let (value, rest) = postcard::take_from_bytes(&body).map_err(|_| FrameError::Malformed)?;
    if !rest.is_empty() {
        return Err(FrameError::Malformed);
    }
    Ok((value, 4 + len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::Request;

    #[tokio::test]
    async fn frame_rejects_oversized_length_before_alloc() {
        let bytes = u32::MAX.to_be_bytes();
        let mut r = &bytes[..];
        let err = read::<Request>(&mut r, MAX_REQUEST_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { .. }));
    }

    #[tokio::test]
    async fn frame_header_then_eof_is_truncated() {
        let bytes = (MAX_REQUEST_BYTES as u32).to_be_bytes();
        let mut r = &bytes[..];
        assert!(matches!(
            read::<Request>(&mut r, MAX_REQUEST_BYTES).await,
            Err(FrameError::Truncated)
        ));
    }

    #[tokio::test]
    async fn frame_clean_eof_is_closed() {
        let mut r = &[][..];
        assert!(matches!(
            read::<Request>(&mut r, MAX_REQUEST_BYTES).await,
            Err(FrameError::Closed)
        ));
    }

    #[tokio::test]
    async fn frame_trailing_bytes_is_malformed() {
        let mut buf = Vec::new();
        write(&mut buf, &Request::Ping { from: None }, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        buf.push(0);
        let len = (buf.len() - 4) as u32;
        buf[..4].copy_from_slice(&len.to_be_bytes());
        let mut r = &buf[..];
        assert!(matches!(
            read::<Request>(&mut r, MAX_REQUEST_BYTES).await,
            Err(FrameError::Malformed)
        ));
    }

    #[tokio::test]
    async fn frame_truncated_is_error() {
        let mut buf = Vec::new();
        write(&mut buf, &Request::Ping { from: None }, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        for cut in 1..buf.len() {
            let mut r = &buf[..cut];
            let err = read::<Request>(&mut r, MAX_REQUEST_BYTES)
                .await
                .unwrap_err();
            assert!(matches!(err, FrameError::Truncated), "cut at {cut}");
        }
    }

    #[tokio::test]
    async fn frame_roundtrip_and_write_limit() {
        let req = Request::Deposit {
            packet: vec![7; 300],
            pow: 9,
        };
        let mut buf = Vec::new();
        write(&mut buf, &req, MAX_REQUEST_BYTES).await.unwrap();
        let mut r = &buf[..];
        assert_eq!(
            read::<Request>(&mut r, MAX_REQUEST_BYTES).await.unwrap(),
            req
        );
        let mut small = Vec::new();
        assert!(matches!(
            write(&mut small, &req, 10).await,
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn frame_garbage_body_is_malformed() {
        let mut buf = 3u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0xff, 0xff, 0xff]);
        let mut r = &buf[..];
        assert!(matches!(
            read::<Request>(&mut r, MAX_REQUEST_BYTES).await,
            Err(FrameError::Malformed)
        ));
    }
}
