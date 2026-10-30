//! Trames : longueur sur 4 octets en big-endian, puis le corps postcard.

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Taille maximale d'une requête (corps seul).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Taille maximale d'une réponse (corps seul).
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("trame trop grande ({len} octets, maximum {max})")]
    TooLarge { len: usize, max: usize },
    #[error("trame tronquée")]
    Truncated,
    #[error("corps de trame invalide")]
    Malformed,
    #[error("erreur d'entrée-sortie : {0}")]
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

/// Écrit une trame ; refuse un corps plus grand que `max`.
pub async fn write<T: Serialize>(
    w: &mut (impl AsyncWrite + Unpin),
    value: &T,
    max: usize,
) -> Result<()> {
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
    w.write_all(&len.to_be_bytes()).await.map_err(io_err)?;
    w.write_all(&body).await.map_err(io_err)?;
    Ok(())
}

/// Lit une trame. La longueur annoncée est vérifiée avant toute allocation.
pub async fn read<T: DeserializeOwned>(r: &mut (impl AsyncRead + Unpin), max: usize) -> Result<T> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await.map_err(io_err)?;
    let len = u32::from_be_bytes(head) as usize;
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(io_err)?;
    postcard::from_bytes(&body).map_err(|_| FrameError::Malformed)
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
    async fn frame_truncated_is_error() {
        let mut buf = Vec::new();
        write(&mut buf, &Request::Ping, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        for cut in 0..buf.len() {
            let mut r = &buf[..cut];
            let err = read::<Request>(&mut r, MAX_REQUEST_BYTES)
                .await
                .unwrap_err();
            assert!(matches!(err, FrameError::Truncated), "coupe à {cut}");
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
