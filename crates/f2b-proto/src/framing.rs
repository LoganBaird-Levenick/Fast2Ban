//! Protocol framing using Fail2Ban delimiters.

pub const CSPROTO_END: &[u8] = b"<F2B_END_COMMAND>";
pub const CSPROTO_CLOSE: &[u8] = b"<F2B_CLOSE_COMMAND>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Message(Vec<u8>),
    Close,
}

#[derive(Debug, Default)]
pub struct MessageBuffer {
    buffer: Vec<u8>,
}

impl MessageBuffer {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    /// Attempts to extract a complete framed message.
    pub fn next_frame(&mut self) -> Option<Frame> {
        let pos = self
            .buffer
            .windows(CSPROTO_END.len())
            .position(|w| w == CSPROTO_END)?;

        let payload = self.buffer[..pos].to_vec();
        self.buffer.drain(..pos + CSPROTO_END.len());

        if payload == CSPROTO_CLOSE {
            Some(Frame::Close)
        } else {
            Some(Frame::Message(payload))
        }
    }
}

pub fn frame_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + CSPROTO_END.len());
    out.extend_from_slice(payload);
    out.extend_from_slice(CSPROTO_END);
    out
}

pub fn close_message() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(CSPROTO_CLOSE);
    out.extend_from_slice(CSPROTO_END);
    out
}
