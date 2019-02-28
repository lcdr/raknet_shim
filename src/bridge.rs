//! Contains the link between RakNet and TcpUdp, as well as abstract packet definitions.
use std::collections::HashMap;
use std::io::Result as Res;
use std::net::{SocketAddr, ToSocketAddrs};

use endio::LERead;
use endio::LEWrite;

use crate::raknet::Connection as RakConn;
use crate::tcpudp::Connection as TcpUdpConn;
use crate::log::packet_name;
use crate::string::ReadStr;
use crate::string::WriteStr;
use crate::Shim;

/// Control messages of the RakNet data-level protocol. Only those that need to be handled by this program are listed.
pub enum MessageType {
	/// First message ever received: The client requests to open a connection.
	OpenConnectionRequest = 9,
	/// We accept the client's request to open a connection.
	OpenConnectionReply = 10,
	/// We refuse the client's request to open a connection.
	NoFreeIncomingConnections = 18,
	/// The client has disconnected voluntarily.
	DisconnectNotification = 19,
}

/// Reliablity types supported by RakNet. `ReliableSequenced` is also one of them but is never used in practice, so it's omitted from this program entirely.
#[derive(Debug, PartialEq)]
pub enum Reliability {
	/// Neither guaranteed to be received nor to be received in the same order as the packets were sent.
	Unreliable,
	/// Not guaranteed to be received. If packets are received out of order, the most recent one is used and older packets are ignored.
	UnreliableSequenced,
	/// Guaranteed to be received at some point. No guarantees about ordering are made.
	Reliable,
	/// Guaranteed to be received, and in the same order as the packets were sent.
	ReliableOrdered,
}

/// Packet data and reliability: The abstract data that connections return from receiving and accept for sending.
pub struct Packet {
	pub reliability: Reliability,
	pub data: Vec<u8>,
}

/// Shims are managed by the main function, so if they need to be modified the command has to be relayed back through this.
pub enum ShimCommand {
	/// Instructs the main function to add a shim to the list of shims, and a remote address to the lookup of remote addresses to local addresses.
	NewShim(SocketAddr, Shim),
}

/// A Bridge connects a RakNet connection with a TcpUdp connection.
pub struct Bridge {
	raknet: RakConn,
	tcpudp: TcpUdpConn,
}

impl Bridge {
	/// Creates a new Bridge from an existing RakNet connection and TcpUdp connection.
	pub fn new(raknet: RakConn, tcpudp: TcpUdpConn) -> Self {
		Bridge { raknet, tcpudp }
	}

	/// Receives any incoming packets on the TcpUdp end, scans them, and sends them on the RakNet end.
	pub fn tcpudp_receive(&mut self, addrs: &HashMap<SocketAddr, SocketAddr>) -> Res<Vec<ShimCommand>> {
		let mut packets = self.tcpudp.receive()?;
		for packet in &packets {
			println!("tcpudp got {}", packet_name(packet));
		}
		let cmds = self.scan_packets(&mut packets, addrs)?;
		self.raknet.send(packets)?;
		Ok(cmds)
	}

	/// Receives any incoming packets on the RakNet end and sends them on the TcpUdp end.
	pub fn raknet_receive(&mut self, data: &[u8]) -> Res<()> {
		let packets = self.raknet.handle_datagram(data)?;
		for packet in &packets {
			println!("raknet got {}", packet_name(packet));
		}
		self.tcpudp.send(packets)?;
		Ok(())
	}

	/**
		Scans packets for certain messages and replaces data if necessary.

		LU servers send IPs in login response and redirection packets. If these packets were passed on unmodified, the client would directly connect to the LU server instead, making this program pointless. Therefore these IPs need to be replaced with those of a relay server, starting one if it doesn't already exist.
	*/
	fn scan_packets(&mut self, packets: &mut Vec<Packet>, addrs: &HashMap<SocketAddr, SocketAddr>) -> Res<Vec<ShimCommand>> {
		let mut cmds = vec![];
		for packet in packets {
			if packet.data.len() > 8 && packet.data[0] == 83 && packet.data[1] == 5 {
				if packet.data[3] == 0 {
					if packet.data[8] == 1 && packet.data.len() > 413 {
						let mut reader = &packet.data[345..];
						let mut host = reader.read_fix()?;
						if host == "localhost" {
							host = "127.0.0.1";
						}
						let port: u16 = (&packet.data[411..]).read()?;
						let connect_addr = (host, port).to_socket_addrs().unwrap().next().unwrap();

						let addr = match addrs.get(&connect_addr) {
							Some(addr) => *addr,
							None => {
								let listen_addr = "127.0.0.1:0".to_socket_addrs().unwrap().next().unwrap();
								let shim = Shim::new(listen_addr, connect_addr)?;
								let listen_addr = shim.local_addr()?;
								cmds.push(ShimCommand::NewShim(connect_addr, shim));
								listen_addr
							}
						};
						let mut writer = &mut packet.data[345..];
						writer.write_fix("127.0.0.1")?;
						let mut writer = &mut packet.data[411..];
						writer.write(addr.port())?;
					}
				} else if packet.data[3] == 14 {
					let mut reader = &packet.data[8..];
					let mut host = reader.read_fix()?;
					if host == "localhost" {
						host = "127.0.0.1";
					}
					let port: u16 = (&packet.data[8+33..]).read()?;
					let connect_addr = (host, port).to_socket_addrs().unwrap().next().unwrap();

					let addr = match addrs.get(&connect_addr) {
						Some(addr) => *addr,
						None => {
							let listen_addr = "127.0.0.1:0".to_socket_addrs().unwrap().next().unwrap();
							let shim = Shim::new(listen_addr, connect_addr)?;
							let listen_addr = shim.local_addr()?;
							cmds.push(ShimCommand::NewShim(connect_addr, shim));
							listen_addr
						}
					};

					let mut writer = &mut packet.data[8..];
					writer.write_fix("127.0.0.1")?;
					let mut writer = &mut packet.data[8+33..];
					writer.write(addr.port())?;
				}
			}
		}
		Ok(cmds)
	}
}

impl Drop for Bridge {
	fn drop(&mut self) {
		println!("Closing bridge");
	}
}
