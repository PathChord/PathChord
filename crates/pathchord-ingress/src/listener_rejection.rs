//! Bounded close after a local protocol rejection has been written.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Deliver the final reply before dropping a socket with unread client input.
/// Winsock may otherwise reset the connection and discard that reply. Never
/// wait indefinitely for a rejected client to send EOF or stop writing.
pub(crate) async fn finish<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let close = async {
        if stream.shutdown().await.is_err() {
            return;
        }
        let mut remaining = 64 * 1024;
        let mut buffer = [0; 4096];
        while remaining > 0 {
            let limit = remaining.min(buffer.len());
            match stream.read(&mut buffer[..limit]).await {
                Ok(0) | Err(_) => break,
                Ok(length) => remaining -= length,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(100), close).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn delivers_rejection_while_discarding_coalesced_client_input() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let request = vec![b'x'; 32 * 1024];
        client.write_all(&request).await.unwrap();
        let owner = tokio::spawn(async move {
            let mut prefix = [0; 4];
            server.read_exact(&mut prefix).await.unwrap();
            server.write_all(b"rejected").await.unwrap();
            finish(&mut server).await;
        });
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"rejected");
        tokio::time::timeout(Duration::from_secs(1), owner)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn silent_rejected_client_cannot_hold_the_owner_open() {
        let (mut server, mut client) = tokio::io::duplex(64);
        server.write_all(b"rejected").await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), finish(&mut server))
            .await
            .unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"rejected");
    }
}
