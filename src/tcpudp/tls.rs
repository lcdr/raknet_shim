/*!
	Alternative drop-in TCP replacement with TLS encryption.
*/
use std::fs;
use std::io::{Read, Write};
use std::io::Result as Res;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;

use rustls::Session;

pub struct Tcp {
	stream: rustls::StreamOwned<rustls::ClientSession, TcpStream>,
}

impl Tcp {
	pub fn connect<A: ToSocketAddrs>(addr: &A) -> Res<Self> {
		let connect_domain = match fs::read_to_string("shim_config.txt") {
			Ok(s) => s,
			Err(_) => String::from("lu.lcdruniverse.org"),
		};

		let mut config = rustls::ClientConfig::new();
		config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

		let dns_name = webpki::DNSNameRef::try_from_ascii_str(&connect_domain).unwrap();
		let sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
		let sock = TcpStream::connect(addr)?;
		sock.set_nonblocking(true)?;

		let mut stream = rustls::StreamOwned::new(sess, sock);

		while stream.sess.is_handshaking() {
			while let Err(e) = stream.sess.complete_io(&mut stream.sock) {
				if e.kind() != std::io::ErrorKind::WouldBlock {
					return Err(e);
				}
				std::thread::sleep(std::time::Duration::from_millis(30));
			}
		}

		Ok(Tcp { stream } )
	}

	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.stream.sock.local_addr()
	}

	pub fn set_nonblocking(&self, nonblocking: bool) -> Res<()> {
		self.stream.sock.set_nonblocking(nonblocking)
	}
}

impl Read for Tcp {
	fn read(&mut self, buf: &mut [u8]) -> Res<usize> {
		self.stream.read(buf)
	}
}

impl Write for Tcp {
	fn write(&mut self, buf: &[u8]) -> Res<usize> {
		self.stream.write(buf)
	}

	fn flush(&mut self) -> Res<()> {
		self.stream.flush()
	}
}
