//! Client socket connection to the Fast2Ban / Fail2Ban server (`CSocket`).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use f2b_proto::{Frame, MessageBuffer, Value, close_message, decode, encode, frame_message};

#[derive(Debug)]
pub struct ClientSocket {
    sock_path: PathBuf,
    stream: Option<UnixStream>,
    timeout: Duration,
}

impl ClientSocket {
    pub fn new(sock_path: impl AsRef<Path>) -> Self {
        Self {
            sock_path: sock_path.as_ref().to_path_buf(),
            stream: None,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn connect(&mut self) -> std::io::Result<()> {
        let stream = UnixStream::connect(&self.sock_path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        self.stream = Some(stream);
        Ok(())
    }

    pub fn is_alive(&mut self) -> bool {
        if self.connect().is_err() {
            return false;
        }
        let res = self.send(&[Value::Str("ping".to_owned())]);
        self.close();
        matches!(res, Ok(Value::Str(s)) if s == "pong")
    }

    /// Send a command list and return the server's return value.
    pub fn send(&mut self, cmd: &[Value]) -> Result<Value, String> {
        if self.stream.is_none() {
            self.connect()
                .map_err(|e| format!("Could not connect to server at {:?}: {e}", self.sock_path))?;
        }

        let stream = self.stream.as_mut().unwrap();

        let req_val = Value::List(cmd.to_vec());
        let payload = encode(&req_val);
        let framed = frame_message(&payload);

        stream
            .write_all(&framed)
            .map_err(|e| format!("Failed to send data to server: {e}"))?;

        let mut msg_buf = MessageBuffer::new();
        let mut chunk = [0u8; 4096];

        loop {
            match stream.read(&mut chunk) {
                Ok(0) => return Err("Connection closed by peer".to_owned()),
                Ok(n) => {
                    msg_buf.feed(&chunk[..n]);
                    if let Some(frame) = msg_buf.next_frame() {
                        match frame {
                            Frame::Message(data) => {
                                let resp = decode(&data)
                                    .map_err(|e| format!("Protocol decode error: {e}"))?;
                                if let Value::Tuple(pair) = &resp {
                                    if pair.len() == 2 {
                                        if pair[0].as_i64() == Some(0) {
                                            return Ok(pair[1].clone());
                                        } else {
                                            let err_msg = pair[1].clone().into_string();
                                            return Err(err_msg);
                                        }
                                    }
                                }
                                return Ok(resp);
                            }
                            Frame::Close => return Err("Server closed connection".to_owned()),
                        }
                    }
                }
                Err(e) => return Err(format!("Error reading from server: {e}")),
            }
        }
    }

    pub fn close(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.write_all(&close_message());
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for ClientSocket {
    fn drop(&mut self) {
        self.close();
    }
}
