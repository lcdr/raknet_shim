//! Debug logging of packet names.
use crate::bridge::Packet;

pub fn packet_name(packet: &Packet) -> String {
	let len = packet.data.len();
	if len == 0 {
		String::from("<Empty packet>")
	} else {
		if packet.data[0] != 83 {
			match packet.data[0] {
				0 => String::from("InternalPing"),
				3 => String::from("ConnectedPong"),
				4 => String::from("ConnectionRequest"),
				14 => String::from("ConnectionRequestAccepted"),
				17 => String::from("NewIncomingConnection"),
				19 => String::from("DisconnectNotification"),
				36 => String::from("ReplicaManagerConstruction"),
				37 => String::from("ReplicaManagerDestruction"),
				39 => String::from("ReplicaManagerSerialize"),
				_ => format!("{}", packet.data[0]),
			}
		} else {
			if len >= 8 {
				match packet.data[1] {
					0 => {
						match packet.data[3] {
							0 => String::from("Handshake"),
							_ => format!("53-{}-0-{}", packet.data[1], packet.data[3]),
						}
					}
					1 => {
						match packet.data[3] {
							0 => String::from("LoginRequest"),
							_ => format!(" 53-{}-0-{}", packet.data[1], packet.data[3]),
						}
					}
					2 => {
						match packet.data[3] {
							1 => String::from("GeneralChatMessage"),
							_ => format!(" 53-{}-0-{}", packet.data[1], packet.data[3]),
						}
					}
					4 => {
						match packet.data[3] {
							1 => String::from("SessionInfo"),
							2 => String::from("CharacterListRequest"),
							4 => String::from("EnterWorld"),
							5 => String::from("GameMessage"),
							15 => String::from("Routing"),
							19 => String::from("LoadComplete"),
							22 => String::from("PositionUpdate"),
							23 => String::from("Mail"),
							25 => String::from("StringCheck"),
							_ => format!("53-{}-0-{}", packet.data[1], packet.data[3]),
						}
					}
					5 => {
						match packet.data[3] {
							0 => String::from("LoginResponse"),
							2 => String::from("LoadWorld"),
							4 => String::from("CharacterData"),
							6 => String::from("CharacterList"),
							12 => String::from("GameMessage"),
							14 => String::from("GeneralChatMessage"),
							49 => String::from("Mail"),
							59 => String::from("Moderation"),
							_ => format!("53-{}-0-{}", packet.data[1], packet.data[3]),
						}
					}
					_ => format!("53-{}-0-{}", packet.data[1], packet.data[3]),
				}
			} else {
				String::from("LU packet too short!")
			}
		}
	}
}
