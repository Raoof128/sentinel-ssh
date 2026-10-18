//! Transport input limits. rmcp's stdio transport buffers a line until it sees a newline, without a bound; a client
//! (or anything that can write to the gateway's stdin) could otherwise grow that buffer without limit.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// The longest JSON-RPC message line accepted. A 16-item batch with full parameters is a few KiB.
pub const MAX_REQUEST_LINE_BYTES: usize = 1 << 20;

/// Passes bytes through, and fails the stream once a line runs past `max` bytes without a newline. The transport then
/// ends, and the server with it: a client that sends such a line is not speaking MCP.
pub struct LineLimited<R> {
    inner: R,
    max: usize,
    line: usize,
}

impl<R> LineLimited<R> {
    pub fn new(inner: R, max: usize) -> Self {
        Self { inner, max, line: 0 }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LineLimited<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let mut line = this.line;
                for &b in &buf.filled()[before..] {
                    line = if b == b'\n' { 0 } else { line + 1 };
                    if line > this.max {
                        // A read that fails hands back no bytes.
                        buf.set_filled(before);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("request line longer than {} bytes", this.max),
                        )));
                    }
                }
                this.line = line;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
