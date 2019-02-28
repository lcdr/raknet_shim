/*!
	A program to transparently translate RakNet 3.25 traffic to TCP and UDP.

	RakNet's protocol is designed to support sending packets with one of multiple reliability modes. To achieve this, the RakNet protocol is layered on top of UDP, and implements the necessary protocol structures and behaviors for ensuring the various reliability modes.

	RakNet offers the modes `Unreliable`, `UnreliableSequenced`, `Reliable`, `ReliableOrdered`, and `ReliableSequenced`. However, in practice (at least for LU specifically), only `UnreliableSequenced` and `ReliableOrdered` are widely used. Unfortunately, the structures and behaviors necessary for the other modes, the complexity required for implementing reliability comparable with TCP on top of UDP, as well as various bugs/artifacts in RakNet's implementation, make the protocol much more complex than necessary.

	RakNet's protocol also rolls its own custom combination of cryptography techniques for encryption. RakNet 3.25 is so niche that it's very unlikely that the protocol has been properly audited for cryptographic correctness, and along with the fact that the protocol is now over 10 years old (version 3.25 is from 2008), it can't be reliably said to be secure.

	Further issues arise if RakNet is used in a closed-source context (as in LU). In this situation the version of RakNet used can't be updated, even if it turns out there are bugs in its implementation. This is especially problematic when the potential security vulnerabilities mentioned above are taken into account.

	To address these issues, this program replaces the RakNet 3.25 protocol with a new protocol, designed to add as little additional complexity as possible. Support for the reliability modes `Reliable` and `ReliableSequenced` are dropped, with `Reliable` converted to `ReliableOrdered`. Instead of basing the protocol on UDP for all reliability modes, UDP is used as a base for `Unreliable` and `UnreliableSequenced` packets, and TCP is used for `ReliableOrdered` packets. This means that the underlying protocols' mechanisms can be fully utilized and the resulting protocol is kept extremely simple.

	For encryption, the TCP connection can be configured to use TLS. As TLS needs a reliable base protocol, and LU only uses unreliable packets for player position updates and not for confidential data, the choice was made not to support encrypted UDP.

	As the LU client is closed-source, its use of the RakNet protocol cannot be replaced directly, and the translation into TCP/UDP needs to be transparent to the client. To accomplish this, this program hosts a RakNet 3.25 server which the client connects to. Traffic is translated on the fly and relayed to a server using the new protocol. LU Redirect packets are intercepted and new relays are spun up to facilitate dynamic connections to multiple servers.

	More information about the new protocol can be found in the documentation for the TcpUdp connection implementation, and info about the translation and interception process can be found in the `Bridge` documentation.
*/
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Result as Res;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::Duration;

mod bridge;
mod log;
mod raknet;
mod string;
mod tcpudp;
use crate::bridge::{Bridge, MessageType, ShimCommand};
use crate::raknet::MAX_PACKET_SIZE;
use crate::raknet::Connection as RakConn;
use crate::tcpudp::Connection as TcpUdpConn;

const SLEEP_TIME: Duration = Duration::from_millis(1000/30);
/// Buffer for receiving RakNet datagrams.
static mut BUF: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];

/// A RakNet server translating and relaying incoming connections to a TcpUdp server.
pub struct Shim {
	/// The remote address to relay connections to.
	connect_addr: SocketAddr,
	/// The RakNet socket. As UDP is a connectionless protocol, there is only one socket no matter how many clients connect to the server.
	raknet: UdpSocket,
	/// The map from an incoming RakNet address to the bridge responsible for handling the specific connection.
	bridges: HashMap<SocketAddr, Bridge>,
}

impl Shim {
	/// Creates a new Shim with the specified local address to listen on and the remote address to relay connections to.
	fn new(listen_addr: SocketAddr, connect_addr: SocketAddr) -> Res<Shim> {
		let raknet = UdpSocket::bind(listen_addr)?;
		raknet.set_nonblocking(true)?;
		println!("Starting new shim");
		Ok(Shim {
			connect_addr,
			raknet,
			bridges: HashMap::new(),
		})
	}

	/// Returns the local address of the RakNet socket. This may not be the same as the `listen_address` passed to `new` if the passed address had 0 as port.
	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.raknet.local_addr()
	}

	/**
		Checks all sockets for incoming packets and handles them if there are any.

		The RakNet socket is checked by the `raknet_step` method, while the TCP/UDP sockets are checked by the bridge's `tcpudp_receive` method.
	*/
	fn step(&mut self, cmds: &mut Vec<ShimCommand>, addrs: &HashMap<SocketAddr, SocketAddr>) -> Res<()> {
		self.raknet_receive()?;
		self.bridges.retain(|_addr, bridge| {
			match bridge.tcpudp_receive(addrs) {
				Ok(cmd) => {
					cmds.extend(cmd);
					true
				}
				Err(err) => {
					if err.kind() == io::ErrorKind::ConnectionReset {
						println!("Connection was reset unexpectedly");
					} else if err.kind() != io::ErrorKind::ConnectionAborted {
						println!("Error: {:?}", err);
					}
					false
				}
			}
		});
		Ok(())
	}

	/**
		Checks the RakNet socket for incoming packets.
	*/
	fn raknet_receive(&mut self) -> Res<()> {
		loop {
			let (length, source) = match self.raknet.recv_from( unsafe {&mut BUF}) {
				Ok(x) => x,
				Err(err) => {
					if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::ConnectionReset {
						return Ok(());
					}
					dbg!(&err);
					return Err(err);
				}
			};
			match self.bridges.get_mut(&source) {
				None => {
					if length <= 2 && unsafe {BUF[0]} == MessageType::OpenConnectionRequest as u8 {
						let response = match self.create_bridge(source) {
							Ok(bridge) => {
								self.bridges.insert(source, bridge);
								MessageType::OpenConnectionReply
							}
							Err(err) => {
								if err.kind() == io::ErrorKind::ConnectionRefused {
									println!("Error: Connection to {} refused", self.connect_addr);
								} else {
									println!("Error: Could not establish connection: {:?}", err);
								}
								MessageType::NoFreeIncomingConnections
							}
						};
						self.raknet.send_to(&[response as u8, 0], &source)?;
					}
				}
				Some(bridge) => {
					if let Err(err) = bridge.raknet_receive( unsafe {&mut &BUF[..length]}) {
						println!("error: {}", err);
						self.bridges.remove(&source);
					}
				}
			}
		}
	}

	fn create_bridge(&self, source: SocketAddr) -> Res<Bridge> {
		let raknet = RakConn::new(self.raknet.try_clone()?, source);
		let tcpudp = TcpUdpConn::new(self.connect_addr)?;
		Ok(Bridge::new(raknet, tcpudp))
	}
}

impl Drop for Shim {
	fn drop(&mut self) {
		println!("Closing shim {}", self.raknet.local_addr().unwrap().port());
	}
}

/**
	The main function.

	This program uses a lot of sockets which all need to be responsive to incoming packets. This means that blocking I/O is not reasonable. At the same time, the system of shims, bridges, and connections is complex enough that it isn't possible to easily use OS polling through a library like `mio`. Therefore, "manual" non-blocking I/O is used: The main function acts as an event loop, periodically checking all shims for incoming packets and sleeping between iterations.

	At the start of the program, the shim corresponding to LU's auth server is created at port 1001. If later interaction results in spinning off new `Shim` instances, they will be handed down to this function and added to the list of shims to check.
*/
fn main() -> Res<()> {
	let connect_domain = match fs::read_to_string("shim_config.txt") {
		Ok(s) => s,
		Err(_) => String::from("lu.lcdruniverse.org"),
	};

	let listen_addr = "127.0.0.1:1001".to_socket_addrs().unwrap().next().unwrap();
	let connect_addr = (&connect_domain[..], 1002).to_socket_addrs().unwrap().next().unwrap();

	let mut addrs = HashMap::new();
	let mut shims = vec![];
	addrs.insert(connect_addr, listen_addr);
	shims.push(Shim::new(listen_addr, connect_addr)?);

	println!("To use this shim, set your client's AUTHSERVERIP in boot.cfg to localhost.");

	loop {
		let mut cmds = vec![];

		for shim in shims.iter_mut() {
			shim.step(&mut cmds, &addrs)?;
		}
		for cmd in cmds {
			match cmd {
				ShimCommand::NewShim(connect_addr, shim) => {
					addrs.insert(connect_addr, shim.local_addr()?);
					shims.push(shim);
				}
			}
		}
		thread::sleep(SLEEP_TIME);
	}
}
