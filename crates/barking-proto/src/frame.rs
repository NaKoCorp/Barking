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
    #[error("flux fermé proprement avant toute trame")]
    Closed,
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

/// Écrit une trame ; refuse un corps plus grand que `max`. Renvoie le nombre
/// d'octets écrits (en-tête compris).
pub async fn write<T: Serialize>(
    w: &mut (impl AsyncWrite + Unpin),
    value: &T,
    max: usize,
) -> Result<usize> {
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
    Ok(4 + body.len())
}

/// Lit une trame. La longueur annoncée est vérifiée avant toute allocation.
pub async fn read<T: DeserializeOwned>(r: &mut (impl AsyncRead + Unpin), max: usize) -> Result<T> {
    Ok(read_counted(r, max).await?.0)
}

/// Comme `read`, et renvoie aussi le nombre d'octets lus (en-tête compris).
pub async fn read_counted<T: DeserializeOwned>(
    r: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> Result<(T, usize)> {
    let mut head = [0u8; 4];
    // EOF avant le premier octet : fermeture propre ; ensuite : tronquée.
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
    // Le tampon grandit au fil des octets reçus : un en-tête seul ne réserve
    // pas `len` octets (pas d'amplification par un pair qui n'envoie rien).
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
        write(&mut buf, &Request::Ping, MAX_REQUEST_BYTES)
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
        write(&mut buf, &Request::Ping, MAX_REQUEST_BYTES)
            .await
            .unwrap();
        for cut in 1..buf.len() {
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
