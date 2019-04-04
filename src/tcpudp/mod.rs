/*!
	The new TCP- and UDP-based protocol.

	The protocol is designed to make full use of the mechanisms of the underlying protocols and be as simple as possible itself.

	Reliable packets are sent over TCP, which provides all necessary mechanisms for reliability and ordering. The only additional mechanism needed is message framing, as TCP is a stream-oriented protocol and doesn't have a concept of distinct messages. To implement this, each message is prefixed with a 32-bit length field (in bytes).

	Unreliable packets are sent over UDP, prefixed with an 8-bit ID for distinguishing between `Unreliable` (ID 0) and `UnreliableSequenced` (ID 1). In the case of `UnreliableSequenced`, a 32-bit sequence number is prefixed as well. To keep the protocol simple, no support for packet splitting is included, unreliable packets must be shorter than the MTU.
*/
#[cfg(not(test))]
mod tls;

use std::io;
use std::io::Result as Res;
#[cfg(test)]
use std::net::TcpStream as Tcp;
use std::net::{ToSocketAddrs, UdpSocket};

use endio::LEWrite;

use crate::BUF;
use crate::bridge::{Packet, Reliability::*};
#[cfg(not(test))]
use self::tls::Tcp;

/// Buffer for keeping packets that were only read in part.
struct BufferOffset {
	reading_length: bool,
	offset: usize,
	length: [u8; 4],
	buffer: Box<[u8]>,
}

pub struct Connection {
	tcp: Tcp,
	udp: UdpSocket,
	seq_num_recv: u32,
	seq_num_send: u32,
	packet: BufferOffset,
}

impl Connection {
	pub fn new<A: ToSocketAddrs>(addr: A) -> Res<Self> {
		let tcp = Tcp::connect(&addr)?;
		let udp = UdpSocket::bind(tcp.local_addr()?)?;
		udp.connect(&addr)?;
		tcp.set_nonblocking(true)?;
		udp.set_nonblocking(true)?;
		Ok(Connection {
			tcp,
			udp,
			seq_num_recv: 0,
			seq_num_send: 0,
			packet: BufferOffset { reading_length: true, offset: 0, length: [0; 4], buffer: Box::new([]) },
		})
	}

	/// Send packets.
	pub fn send(&mut self, packets: Vec<Packet>) -> Res<()> {
		for packet in packets {
			match packet.reliability {
				Unreliable => {
					let mut vec = Vec::with_capacity(packet.data.len()+1);
					vec.write(0u8)?;
					vec.write(&*packet.data)?;
					self.udp.send(&vec)?;
				}
				UnreliableSequenced => {
					let seq_num = self.seq_num_send;
					self.seq_num_send = self.seq_num_send.wrapping_add(1);
					let mut vec = Vec::with_capacity(packet.data.len()+1+4);
					vec.write(1u8)?;
					vec.write(seq_num)?;
					vec.write(&*packet.data)?;
					self.udp.send(&vec)?;
				}
				_ => {
					self.tcp.write(packet.data.len() as u32)?;
					std::io::Write::write(&mut self.tcp, &packet.data)?;
				}
			}
		}
		Ok(())
	}

	/// Receive packets.
	pub fn receive(&mut self) -> Res<Vec<Packet>> {
		let mut packets = vec![];
		match self.receive_tcp(&mut packets) {
			Ok(()) => unreachable!(),
			Err(err) => {
				if err.kind() != io::ErrorKind::WouldBlock {
					return Err(err);
				}
			}
		}
		match self.receive_udp(&mut packets) {
			Ok(()) => unreachable!(),
			Err(err) => {
				if err.kind() != io::ErrorKind::WouldBlock {
					return Err(err);
				}
			}
		}
		Ok(packets)
	}

	/// Receive packets from UDP.
	fn receive_udp(&mut self, packets: &mut Vec<Packet>) -> Res<()> {
		use endio::LERead;

		loop {
			let len = self.udp.recv( unsafe {&mut BUF})?;
			let reader = unsafe { &mut &BUF[..] };
			let rel: u8 = reader.read()?;
			if rel == 0 {
				let packet = Packet { reliability: Unreliable, data: unsafe { Box::from(&BUF[1..len]) }};
				packets.push(packet);
			} else if rel == 1 {
				let seq_num: u32 = reader.read()?;
				if seq_num.wrapping_sub(self.seq_num_recv) < u32::max_value() / 2 {
					self.seq_num_recv = seq_num.wrapping_add(1);
					let packet = Packet { reliability: UnreliableSequenced, data: unsafe { Box::from(&BUF[5..len]) }};
					packets.push(packet);
				}
			} else { panic!(); }
		}
	}

	/// Receive packets from TCP.
	fn receive_tcp(&mut self, packets: &mut Vec<Packet>) -> Res<()> {
		use std::io::Read;

		loop {
			if self.packet.reading_length {
				while self.packet.offset < self.packet.length.len() {
					let n = self.tcp.read(&mut self.packet.length[self.packet.offset..])?;
					if n == 0 {
						return Err(io::Error::new(io::ErrorKind::WouldBlock, ""));
					}
					self.packet.offset += n;
				}
				self.packet.reading_length = false;
				self.packet.offset = 0;
				self.packet.buffer = vec![0; u32::from_le_bytes(self.packet.length) as usize].into_boxed_slice();
			}
			while self.packet.offset < self.packet.buffer.len() {
				let n = self.tcp.read(&mut self.packet.buffer[self.packet.offset..])?;
				if n == 0 {
					return Err(io::Error::new(io::ErrorKind::WouldBlock, ""));
				}
				self.packet.offset += n;
			}
			self.packet.reading_length = true;
			self.packet.offset = 0;
			let mut b = Box::from(&[][..]);
			std::mem::swap(&mut self.packet.buffer, &mut b);
			let pkt = Packet { data: b, reliability: ReliableOrdered };
			packets.push(pkt);
		}
	}
}

#[cfg(test)]
mod tests_tcp {
	use std::io;
	use std::net::{Shutdown, TcpListener, TcpStream};
	use endio::LERead;
	use endio::LEWrite;
	use super::Connection;
	use super::Packet;
	use super::ReliableOrdered;

	fn setup() -> (Connection, TcpStream) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let client = Connection::new(listener.local_addr().unwrap()).unwrap();
		let server = listener.accept().unwrap().0;
		(client, server)
	}

	#[test]
	fn recv_whole() {
		let (mut client, mut server) = setup();
		server.write(4u32).unwrap();
		server.write(1u16).unwrap();
		server.write(2u16).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets[0].reliability, ReliableOrdered);
		assert_eq!(&*packets[0].data, b"\x01\x00\x02\x00");
	}

	#[test]
	fn recv_partial_len_before() {
		let (mut client, mut server) = setup();
		server.write(1u16).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 0);
		server.write(0u16).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 0);
		server.write(0u8).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 1);
		assert_eq!(packets[0].data.len(), 1);
	}

	#[test]
	fn recv_partial_len_after() {
		let (mut client, mut server) = setup();
		server.write(1u32).unwrap();
		server.write(0u8).unwrap();
		server.write(1u16).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 1);
		server.write(0u16).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 0);
		server.write(0u8).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 1);
		assert_eq!(packets[0].data.len(), 1);
	}

	#[test]
	fn recv_partial_data() {
		let (mut client, mut server) = setup();
		server.write(4u32).unwrap();
		server.write(1u16).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 0);
		server.write(2u16).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 1);
		assert_eq!(&*packets[0].data, b"\x01\x00\x02\x00");
	}

	#[test]
	fn send_ok() {
		let (mut client, mut server) = setup();
		let packets = vec![Packet { reliability: ReliableOrdered, data: Box::new([42]) }];
		client.send(packets).unwrap();
		assert_eq!(server.read::<u32>().unwrap(), 1);
		assert_eq!(server.read::<u8>().unwrap(), 42);
	}

	#[test]
	fn send_shutdown() {
		let (mut client, server) = setup();
		server.shutdown(Shutdown::Both).unwrap();
		let packets = vec![Packet { reliability: ReliableOrdered, data: Box::new([42]) }];
		assert_eq!(client.send(packets).unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
	}
}

#[cfg(test)]
mod tests_udp {
	use std::net::{TcpListener, UdpSocket};
	use crate::BUF;
	use super::{Connection, Packet, Unreliable, UnreliableSequenced};

	fn setup() -> (Connection, UdpSocket) {
		let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let	udp_server = UdpSocket::bind(tcp_listener.local_addr().unwrap()).unwrap();
		let client = Connection::new(tcp_listener.local_addr().unwrap()).unwrap();
		tcp_listener.accept().unwrap();
		(client, udp_server)
	}

	#[test]
	fn recv_unrel() {
		let (mut client, server) = setup();
		let data = b"\x00hello";
		server.send_to(data, client.udp.local_addr().unwrap()).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets[0].reliability, Unreliable);
		assert_eq!(&*packets[0].data, b"hello");
	}

	#[test]
	fn recv_unrel_seq() {
		let (mut client, server) = setup();
		let data = b"\x01\x00\x00\x00\x00hello";
		server.send_to(data, client.udp.local_addr().unwrap()).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets[0].reliability, UnreliableSequenced);
		assert_eq!(&*packets[0].data, b"hello");
	}

	#[test]
	fn recv_unrel_seq_out_of_order() {
		let (mut client, server) = setup();
		client.seq_num_recv = 1;
		let data = b"\x01\x00\x00\x00\x00hello";
		server.send_to(data, client.udp.local_addr().unwrap()).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets.len(), 0);
	}

	#[test]
	fn recv_unrel_seq_overflow() {
		let (mut client, server) = setup();
		client.seq_num_recv = u32::max_value();
		let data = b"\x01\xff\xff\xff\xffhello";
		server.send_to(data, client.udp.local_addr().unwrap()).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets[0].reliability, UnreliableSequenced);
		assert_eq!(&*packets[0].data, b"hello");
	}

	#[test]
	fn recv_unrel_seq_wrap() {
		let (mut client, server) = setup();
		client.seq_num_recv = u32::max_value();
		let data = b"\x01\x00\x00\x00\x00hello";
		server.send_to(data, client.udp.local_addr().unwrap()).unwrap();
		let packets = client.receive().unwrap();
		assert_eq!(packets[0].reliability, UnreliableSequenced);
		assert_eq!(&*packets[0].data, b"hello");
	}

	#[test]
	fn send_unrel() {
		let (mut client, server) = setup();
		let packets = vec![Packet { reliability: Unreliable, data: Box::new(*b"hello") }];
		client.send(packets).unwrap();
		let len = server.recv_from(unsafe { &mut BUF }).unwrap().0;
		assert_eq!(unsafe { &BUF[..len] }, b"\x00hello");
	}

	#[test]
	fn send_unrel_seq() {
		let (mut client, server) = setup();
		client.seq_num_send = u32::max_value();
		let packets = vec![Packet { reliability: UnreliableSequenced, data: Box::new(*b"hello") }];
		client.send(packets).unwrap();
		let len = server.recv_from(unsafe { &mut BUF }).unwrap().0;
		assert_eq!(unsafe { &BUF[..len] }, b"\x01\xff\xff\xff\xffhello");
	}
}
