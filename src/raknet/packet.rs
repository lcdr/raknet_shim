use std::io::Result as Res;

use endio::{Deserialize, LERead, LEWrite, LittleEndian, Serialize};
use endio_bit::{BitReader, BitWriter};

use crate::bridge::{Packet, Reliability};
use super::comp::Compressed;

#[derive(Clone, PartialEq)]
pub enum ReliabilityData {
	Unreliable,
	UnreliableSequenced(u32),
	Reliable,
	ReliableOrdered(u32),
}

impl From<ReliabilityData> for Reliability {
	fn from(rel: ReliabilityData) -> Self {
		match rel {
			ReliabilityData::Unreliable => Reliability::Unreliable,
			ReliabilityData::UnreliableSequenced(_) => Reliability::UnreliableSequenced,
			ReliabilityData::Reliable => Reliability::Reliable,
			ReliabilityData::ReliableOrdered(_) => Reliability::ReliableOrdered,
		}
	}
}

impl<R: std::io::Read> Deserialize<LittleEndian, BitReader<R>> for ReliabilityData {
	fn deserialize(reader: &mut BitReader<R>) -> Res<Self> {
		let id = reader.read_bits(3)?;
		Ok(match id {
			0 => ReliabilityData::Unreliable,
			1 => {
				let ordering_channel = reader.read_bits(5)?;
				assert!(ordering_channel == 0);
				let ord = reader.read()?;
				ReliabilityData::UnreliableSequenced(ord)
			}
			2 => ReliabilityData::Reliable,
			3 => {
				let ordering_channel = reader.read_bits(5)?;
				assert!(ordering_channel == 0);
				let ord = reader.read()?;
				ReliabilityData::ReliableOrdered(ord)
			}
			_ => panic!("unknown reliability id"),
		})
	}
}

impl<W: std::io::Write> Serialize<LittleEndian, BitWriter<W>> for &ReliabilityData {
	fn serialize(self, writer: &mut BitWriter<W>) -> Res<()> {
		let val = match self {
			ReliabilityData::Unreliable => 0,
			ReliabilityData::UnreliableSequenced(_) => 1,
			ReliabilityData::Reliable => 2,
			ReliabilityData::ReliableOrdered(_) => 3,
		};
		writer.write_bits(val, 3)?;
		match self {
			ReliabilityData::UnreliableSequenced(ord) | ReliabilityData::ReliableOrdered(ord) => {
				writer.write_bits(0, 5)?; // ordering channel, no one ever uses anything else than 0
				writer.write(*ord)?;
			}
			_ => {}
		}
		Ok(())
	}
}

pub struct SplitPacketInfo {
	pub id: u16,
	pub index: u32,
	pub count: u32,
}

impl<R: std::io::Read> Deserialize<LittleEndian, BitReader<R>> for SplitPacketInfo {
	fn deserialize(reader: &mut BitReader<R>) -> Res<Self> {
		let id = reader.read()?;
		let index = u32::from(reader.read::<Compressed<u32>>()?);
		let count = u32::from(reader.read::<Compressed<u32>>()?);
		Ok(SplitPacketInfo {
			id,
			index,
			count,
		})
	}
}

impl<W: std::io::Write> Serialize<LittleEndian, BitWriter<W>> for &SplitPacketInfo {
	fn serialize(self, writer: &mut BitWriter<W>) -> Res<()> {
		writer.write(self.id)?;
		writer.write(Compressed::<u32>(self.index))?;
		writer.write(Compressed::<u32>(self.count))
	}
}

pub struct RaknetPacket {
	pub message_number: u32,
	pub rel_data: ReliabilityData,
	pub split_packet_info: Option<SplitPacketInfo>,
	pub data: Vec<u8>,
}

impl From<RaknetPacket> for Packet {
	fn from(packet: RaknetPacket) -> Packet {
		Packet { reliability: Reliability::from(packet.rel_data), data: packet.data }
	}
}

impl<R: std::io::Read> Deserialize<LittleEndian, BitReader<R>> for RaknetPacket {
	fn deserialize(reader: &mut BitReader<R>) -> Res<Self> {
		let message_number = reader.read()?;
		let rel_data = reader.read()?;
		let split_packet_info = match reader.read_bit()? {
			false => None,
			true => Some(reader.read()?),
		};
		let length = u16::from(reader.read::<Compressed<u16>>()?);
		reader.align();
		let mut data = vec![0; (length / 8) as usize];
		std::io::Read::read_exact(reader, &mut data)?;
		Ok(RaknetPacket {
			message_number,
			rel_data,
			split_packet_info,
			data,
		})
	}
}

impl<W: std::io::Write> Serialize<LittleEndian, BitWriter<W>> for &RaknetPacket {
	fn serialize(self, writer: &mut BitWriter<W>) -> Res<()> {
		writer.write(self.message_number)?;
		writer.write(&self.rel_data)?;
		writer.write_bit(self.split_packet_info.is_some())?;
		if let Some(info) = &self.split_packet_info {
			writer.write(info)?;
		}
		writer.write(Compressed::<u16>(self.data.len() as u16 * 8))?;
		writer.align()?;
		writer.write(&self.data)
	}
}
