use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

/// Encapsulates message data to be sent between the game's client and agents.
///
/// A `Packet` contains a field `message`, which specifies a request or a response, and
/// an optional field `msg_sig` which contains a signature of `message` by the sender.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Packet {
    /// A message containing the data to be sent.
    pub message: Vec<u8>,
    /// An optional signature of the message for authentication purposes.
    pub msg_sig: Option<Vec<u8>>,
}

impl Packet {
    pub fn new(message: Vec<u8>, msg_sig: Option<Vec<u8>>) -> Self {
        Packet { message, msg_sig }
    }

    /// Builds a new instance of `Packet`, containing a message `message` and an optional message
    /// signature `msg_sig`, and returns it serialized into binary format.
    pub fn build_packet(
        message: Vec<u8>,
        msg_sig: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, bincode::Error> {
        let packet = Self::new(message, msg_sig);
        serialize(&packet)
    }

    /// Receives a byte array `data`, expected to be in binary format, and attempts to deserialize
    /// it into an instance of `Packet`. Returns `bincode::Error` if the format of `data` is invalid.
    pub fn unpack(data: &[u8]) -> Result<Self, bincode::Error> {
        deserialize(data)
    }
}

/// Represents the outcome of a relay agent's attempt to query an individual peer while
/// processing a `MsgFetchValues` on the game client's behalf.
///
/// A relay must report one `PeerResult` per peer it was asked about, rather than simply
/// omitting peers it doesn't want the client to hear from - this makes suppression of a live
/// peer's reply an explicit, attributable claim instead of an invisible silent drop.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum PeerResult {
    /// The queried peer's own signed `MsgSendValue` packet, forwarded verbatim.
    Reply(Packet),
    /// The relay's own claim (not signed by the named peer) that `agent_id` could not be
    /// reached. Unlike `Reply`, this carries no cryptographic proof on its own.
    Unreachable(usize),
}

// ******************************************************************************************
// ************************************* UNIT TESTS *****************************************
// ******************************************************************************************

#[cfg(test)]
mod tests {
    use super::*;

    // Test that a Packet with a signature round-trips through build_packet/unpack unchanged
    #[test]
    fn test_build_and_unpack_packet_with_signature() {
        let message = b"hello".to_vec();
        let msg_sig = b"signature-bytes".to_vec();

        let packet_bytes = Packet::build_packet(message.clone(), Some(msg_sig.clone())).unwrap();
        let packet = Packet::unpack(&packet_bytes).unwrap();

        assert_eq!(packet.message, message);
        assert_eq!(packet.msg_sig, Some(msg_sig));
    }

    // Test that a Packet without a signature round-trips through build_packet/unpack unchanged
    #[test]
    fn test_build_and_unpack_packet_without_signature() {
        let message = b"hello".to_vec();

        let packet_bytes = Packet::build_packet(message.clone(), None).unwrap();
        let packet = Packet::unpack(&packet_bytes).unwrap();

        assert_eq!(packet.message, message);
        assert_eq!(packet.msg_sig, None);
    }

    // Test that unpacking malformed bytes returns an error instead of panicking
    #[test]
    fn test_unpack_invalid_bytes_returns_err() {
        let garbage = vec![1, 2, 3];
        assert!(Packet::unpack(&garbage).is_err());
    }

    // Test that PeerResult::Reply serializes and deserializes without losing data, guarding the
    // MsgFwdValues wire format against a broken derive
    #[test]
    fn test_peer_result_reply_round_trip() {
        let packet = Packet::new(b"value".to_vec(), Some(b"sig".to_vec()));
        let peer_result = PeerResult::Reply(packet.clone());

        let serialized = serialize(&peer_result).unwrap();
        let deserialized: PeerResult = deserialize(&serialized).unwrap();

        assert_eq!(deserialized, PeerResult::Reply(packet));
    }

    // Test that PeerResult::Unreachable serializes and deserializes without losing data
    #[test]
    fn test_peer_result_unreachable_round_trip() {
        let peer_result = PeerResult::Unreachable(42);

        let serialized = serialize(&peer_result).unwrap();
        let deserialized: PeerResult = deserialize(&serialized).unwrap();

        assert_eq!(deserialized, PeerResult::Unreachable(42));
    }
}
