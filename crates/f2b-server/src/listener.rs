//! Unix domain socket listener (`AsyncServer` in fail2ban).

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use f2b_proto::{Frame, MessageBuffer, decode, encode, frame_message};

use crate::server::Server;
use crate::transmitter::Transmitter;

#[derive(Debug)]
pub struct AsyncServer {
    sock_path: PathBuf,
    listener: UnixListener,
    server: Arc<Mutex<Server>>,
    transmitter: Arc<Transmitter>,
    running: Arc<AtomicBool>,
}

impl AsyncServer {
    pub fn bind(sock_path: impl AsRef<Path>, server: Arc<Mutex<Server>>) -> std::io::Result<Self> {
        let path = sock_path.as_ref().to_path_buf();
        if path.exists() {
            let _ = fs::remove_file(&path);
        }

        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;

        let transmitter = Arc::new(Transmitter::new(server.clone()));
        let running = Arc::new(AtomicBool::new(true));

        Ok(Self {
            sock_path: path,
            listener,
            server,
            transmitter,
            running,
        })
    }

    pub fn sock_path(&self) -> &Path {
        &self.sock_path
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = fs::remove_file(&self.sock_path);
    }

    /// Run the server loop in a background thread, together with the runner
    /// thread that drives the jails (log reading, bans, unbans).
    pub fn start_background(&self) -> std::io::Result<thread::JoinHandle<()>> {
        let running = self.running.clone();
        let listener = self.listener.try_clone()?;
        listener.set_nonblocking(true)?;
        let transmitter = self.transmitter.clone();
        let sock_path = self.sock_path.clone();
        let server = self.server.clone();
        let runner_running = running.clone();
        let runner = thread::Builder::new()
            .name("f2b/server".to_owned())
            .spawn(move || {
                while runner_running.load(Ordering::SeqCst) {
                    if !Server::tick(&server) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            })?;

        Ok(thread::spawn(move || {
            while running.load(Ordering::SeqCst) && transmitter.is_running() {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let tx = transmitter.clone();
                        let is_running = running.clone();
                        thread::spawn(move || {
                            handle_client(stream, &tx, &is_running);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            let _ = fs::remove_file(&sock_path);
            let _ = runner.join();
        }))
    }
}

fn handle_client(mut stream: UnixStream, transmitter: &Transmitter, running: &AtomicBool) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut msg_buf = MessageBuffer::new();
    let mut chunk = [0u8; 4096];

    while running.load(Ordering::SeqCst) && transmitter.is_running() {
        match stream.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                msg_buf.feed(&chunk[..n]);
                while let Some(frame) = msg_buf.next_frame() {
                    match frame {
                        Frame::Close => return,
                        Frame::Message(payload) => {
                            let response_val = match decode(&payload) {
                                Ok(req) => transmitter.proceed(req),
                                Err(e) => f2b_proto::Value::Tuple(vec![
                                    f2b_proto::Value::Int(1),
                                    f2b_proto::Value::Exception(format!("PROTO-error: {e}")),
                                ]),
                            };
                            let encoded = encode(&response_val);
                            let framed = frame_message(&encoded);
                            if stream.write_all(&framed).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

impl Drop for AsyncServer {
    fn drop(&mut self) {
        self.stop();
    }
}
