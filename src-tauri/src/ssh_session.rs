// SSH Session Management for Warp_Open
// Provides SSH terminal connections alongside local PTY sessions

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use ssh2::Session;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConnectionInfo {
    pub host: String,
    pub port: u16,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshInfo {
    pub id: u32,
    pub host: String,
    pub username: String,
    pub connected: bool,
}

pub struct SshSession {
    session: Session,
    channel: ssh2::Channel,
    output_buffer: Arc<Mutex<Vec<u8>>>,
    reader_thread: Option<JoinHandle<()>>,
    connected: bool,
    info: SshConnectionInfo,
}

impl SshSession {
    /// Connect to an SSH server with password authentication
    pub fn connect_password(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<Self, String> {
        eprintln!("[SSH] Connecting to {}@{}:{}", username, host, port);

        // Connect TCP
        let tcp = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| format!("TCP connection failed: {}", e))?;

        // Create SSH session
        let mut session = Session::new()
            .map_err(|e| format!("Failed to create SSH session: {}", e))?;

        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|e| format!("SSH handshake failed: {}", e))?;

        // Authenticate with password
        session.userauth_password(username, password)
            .map_err(|e| format!("Authentication failed: {}", e))?;

        if !session.authenticated() {
            return Err("Authentication failed".to_string());
        }

        eprintln!("[SSH] Authenticated successfully");

        // Open a shell channel
        let mut channel = session.channel_session()
            .map_err(|e| format!("Failed to open channel: {}", e))?;

        // Request PTY
        channel.request_pty("xterm-256color", None, Some((80, 24, 0, 0)))
            .map_err(|e| format!("Failed to request PTY: {}", e))?;

        // Start shell
        channel.shell()
            .map_err(|e| format!("Failed to start shell: {}", e))?;

        // Set non-blocking mode
        session.set_blocking(false);

        let output_buffer = Arc::new(Mutex::new(Vec::new()));

        Ok(Self {
            session,
            channel,
            output_buffer,
            reader_thread: None,
            connected: true,
            info: SshConnectionInfo {
                host: host.to_string(),
                port,
                username: username.to_string(),
            },
        })
    }

    /// Connect to an SSH server with key file authentication
    pub fn connect_key(
        host: &str,
        port: u16,
        username: &str,
        private_key_path: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, String> {
        eprintln!("[SSH] Connecting to {}@{}:{} with key", username, host, port);

        // Connect TCP
        let tcp = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| format!("TCP connection failed: {}", e))?;

        // Create SSH session
        let mut session = Session::new()
            .map_err(|e| format!("Failed to create SSH session: {}", e))?;

        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|e| format!("SSH handshake failed: {}", e))?;

        // Expand key path
        let expanded_key = shellexpand::tilde(private_key_path).to_string();
        let key_path = std::path::Path::new(&expanded_key);

        // Authenticate with key
        session.userauth_pubkey_file(username, None, key_path, passphrase)
            .map_err(|e| format!("Key authentication failed: {}", e))?;

        if !session.authenticated() {
            return Err("Authentication failed".to_string());
        }

        eprintln!("[SSH] Authenticated with key successfully");

        // Open a shell channel
        let mut channel = session.channel_session()
            .map_err(|e| format!("Failed to open channel: {}", e))?;

        // Request PTY
        channel.request_pty("xterm-256color", None, Some((80, 24, 0, 0)))
            .map_err(|e| format!("Failed to request PTY: {}", e))?;

        // Start shell
        channel.shell()
            .map_err(|e| format!("Failed to start shell: {}", e))?;

        // Set non-blocking mode
        session.set_blocking(false);

        let output_buffer = Arc::new(Mutex::new(Vec::new()));

        Ok(Self {
            session,
            channel,
            output_buffer,
            reader_thread: None,
            connected: true,
            info: SshConnectionInfo {
                host: host.to_string(),
                port,
                username: username.to_string(),
            },
        })
    }

    /// Send input to the SSH channel
    pub fn write_input(&mut self, data: &[u8]) -> Result<(), String> {
        if !self.connected {
            return Err("SSH session not connected".to_string());
        }

        self.channel.write_all(data)
            .map_err(|e| format!("Failed to write to SSH channel: {}", e))?;
        self.channel.flush()
            .map_err(|e| format!("Failed to flush SSH channel: {}", e))?;

        Ok(())
    }

    /// Read available output from the SSH channel
    pub fn read_output(&mut self) -> Result<String, String> {
        if !self.connected {
            return Ok(String::new());
        }

        let mut buffer = [0u8; 4096];
        let mut output = Vec::new();

        // Read from stdout
        loop {
            match self.channel.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("Read error: {}", e)),
            }
        }

        // Read from stderr
        loop {
            match self.channel.stderr().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("Stderr read error: {}", e)),
            }
        }

        // Check if channel closed
        if self.channel.eof() {
            self.connected = false;
            eprintln!("[SSH] Channel closed");
        }

        Ok(String::from_utf8_lossy(&output).to_string())
    }

    /// Resize the PTY
    pub fn resize(&mut self, cols: u32, rows: u32) -> Result<(), String> {
        if !self.connected {
            return Err("SSH session not connected".to_string());
        }

        self.channel.request_pty_size(cols, rows, None, None)
            .map_err(|e| format!("Failed to resize PTY: {}", e))?;

        Ok(())
    }

    /// Close the SSH session
    pub fn close(&mut self) -> Result<(), String> {
        if self.connected {
            let _ = self.channel.close();
            let _ = self.channel.wait_close();
            self.connected = false;
            eprintln!("[SSH] Session closed");
        }
        Ok(())
    }

    /// Check if session is connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get connection info
    pub fn get_info(&self) -> &SshConnectionInfo {
        &self.info
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Registry for managing multiple SSH sessions
pub struct SshRegistry {
    pub sessions: Arc<Mutex<HashMap<u32, SshSession>>>,
    next_id: Arc<Mutex<u32>>,
}

impl SshRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    pub fn register(&self, session: SshSession) -> u32 {
        let mut next_id = self.next_id.lock().unwrap();
        let id = *next_id;
        *next_id += 1;

        self.sessions.lock().unwrap().insert(id, session);
        eprintln!("[SshRegistry] Registered session with ID: {}", id);

        id
    }

    pub fn get(&self, id: u32) -> Option<std::sync::MutexGuard<'_, HashMap<u32, SshSession>>> {
        let sessions = self.sessions.lock().unwrap();
        if sessions.contains_key(&id) {
            Some(sessions)
        } else {
            None
        }
    }

    pub fn remove(&self, id: u32) -> Option<SshSession> {
        self.sessions.lock().unwrap().remove(&id)
    }

    pub fn list(&self) -> Vec<SshInfo> {
        self.sessions.lock().unwrap()
            .iter()
            .map(|(id, session)| SshInfo {
                id: *id,
                host: session.info.host.clone(),
                username: session.info.username.clone(),
                connected: session.connected,
            })
            .collect()
    }
}

impl Default for SshRegistry {
    fn default() -> Self {
        Self::new()
    }
}
