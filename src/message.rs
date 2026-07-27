use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

use crate::agent_config::AgentConfig;
use crate::packet::PeerResult;

/// Represents actions used by the game client and agents to communicate among themselves.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Message {
    /// Used to request the receiving agent's value. Should expect a `MsgSendValue` as a reply.
    MsgQueryValue,
    /// Used by an agent to send its value as a reply to a `MsgQueryValue`.
    MsgSendValue { agent_id: usize, value: u64 },
    /// Used by the game's client to kill an active agent.
    MsgKillAgent { agent_id: usize },
    /// Used by the game's client to request an agent to query other agents' values.
    MsgFetchValues {
        agent_id: usize,
        peer_addresses: Vec<AgentConfig>,
    },
    /// Used by agents to forward other agents' values to the game's client. Contains one
    /// `PeerResult` per peer the sending agent was asked to query, accounting for peers whose
    /// replies could not be obtained instead of omitting them.
    MsgFwdValues {
        agent_id: usize,
        peer_results: Vec<PeerResult>,
    },
}
// NOTE: It would be an improvement to include nonces in messages in order to prevent replay attacks.

impl Message {
    /// Builds and returns a `MsgQueryValue` serialized into binary format using bincode.
    /// Takes no parameters.
    pub fn build_msg_query_value() -> Result<Vec<u8>, bincode::Error> {
        let message = Message::MsgQueryValue.serialize_message()?;
        Ok(message)
    }

    /// Builds a `MsgFetchValues` containing a target agent ID `agent_id` and a list of
    /// peer_addresses as a `Vec<AgentConfig>`. Returns the message serialized into binary format
    /// using bincode.
    pub fn build_msg_fetch_values(
        agent_id: usize,
        peers: &Vec<AgentConfig>,
    ) -> Result<Vec<u8>, bincode::Error> {
        let message = Message::MsgFetchValues {
            agent_id,
            peer_addresses: peers.to_vec(),
        }
        .serialize_message()?;
        Ok(message)
    }

    /// Builds a `MsgFwdValues` containing the sending agent's ID `agent_id` and a
    /// `Vec<PeerResult>` containing the outcome of querying each requested peer, to be forwarded
    /// to the game's client. Returns the message serialized into binary format using bincode.
    pub fn build_msg_fwd_values(
        agent_id: usize,
        peer_results: &Vec<PeerResult>,
    ) -> Result<Vec<u8>, bincode::Error> {
        let message = Message::MsgFwdValues {
            agent_id,
            peer_results: peer_results.to_vec(),
        }
        .serialize_message()?;
        Ok(message)
    }

    /// Builds a `MsgSendValue` containing `value` and `agent_id` and returns it serialized into
    /// binary format.
    pub fn build_msg_send_value(value: u64, agent_id: usize) -> Result<Vec<u8>, bincode::Error> {
        let message = Message::MsgSendValue { value, agent_id }.serialize_message()?;
        Ok(message)
    }

    /// Builds a `MsgKillAgent` containing the identifier of the agent to be killed, `agent_id`.
    /// Returns the message serialized into binary format.
    pub fn build_msg_kill_agent(agent_id: usize) -> Result<Vec<u8>, bincode::Error> {
        let message = Message::MsgKillAgent { agent_id }.serialize_message()?;
        Ok(message)
    }

    /// Serializes a variant of `Message` into binary format using bincode.
    pub fn serialize_message(&self) -> Result<Vec<u8>, bincode::Error> {
        serialize(&self)
    }

    /// Deserializes `message_bytes` from binary format into a variant of `Message`. Returns
    /// `bincode::Error` if the format of `message_bytes` is invalid.
    pub fn deserialize_message(message_bytes: &[u8]) -> Result<Message, bincode::Error> {
        deserialize(message_bytes)
    }
}

// ******************************************************************************************
// ************************************* UNIT TESTS *****************************************
// ******************************************************************************************

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    #[test]
    fn test_build_msg_query_value_ok() {
        let message = Message::build_msg_query_value();
        assert!(message.is_ok());
        assert!(!message.unwrap().is_empty());
    }

    #[test]
    fn test_build_msg_fetch_values_ok() {
        let agent_id = 1;
        let peers = vec![
            AgentConfig::new(
                1,
                "127.0.0.1",
                9001,
                "Hv9PImawhJ9+0ulJ/dlKjxTu+vKcKnyoJG5ahh4+DjY=",
            ),
            AgentConfig::new(
                2,
                "127.0.0.1",
                9002,
                "Hv9PImawhJ9+0ulJ/dlKjxTu+vKcKnyoJG5ahh4+DjY=",
            ),
        ];

        let message = Message::build_msg_fetch_values(agent_id, &peers);
        assert!(message.is_ok());

        assert_eq!(
            Message::deserialize_message(&message.unwrap()).unwrap(),
            Message::MsgFetchValues {
                agent_id: 1,
                peer_addresses: vec![
                    AgentConfig::new(
                        1,
                        "127.0.0.1",
                        9001,
                        "Hv9PImawhJ9+0ulJ/dlKjxTu+vKcKnyoJG5ahh4+DjY=",
                    ),
                    AgentConfig::new(
                        2,
                        "127.0.0.1",
                        9002,
                        "Hv9PImawhJ9+0ulJ/dlKjxTu+vKcKnyoJG5ahh4+DjY=",
                    ),
                ]
            }
        );
    }

    #[test]
    fn build_msg_send_value_ok() {
        let message = Message::build_msg_send_value(10, 1);
        assert!(message.is_ok());

        assert_eq!(
            Message::deserialize_message(&message.unwrap()).unwrap(),
            Message::MsgSendValue {
                agent_id: 1,
                value: 10,
            }
        );
    }

    #[test]
    fn build_msg_kill_agent_ok() {
        let message = Message::build_msg_kill_agent(7);
        assert!(message.is_ok());

        assert_eq!(
            Message::deserialize_message(&message.unwrap()).unwrap(),
            Message::MsgKillAgent { agent_id: 7 }
        );
    }

    #[test]
    fn build_msg_fwd_values_ok() {
        let message1 = Message::build_msg_send_value(10, 1).unwrap();
        let packet1 = Packet::new(message1.clone(), None);

        let peer_results = vec![PeerResult::Reply(packet1), PeerResult::Unreachable(2)];

        let msg_fwd_values = Message::build_msg_fwd_values(50, &peer_results);

        assert_eq!(
            Message::deserialize_message(&msg_fwd_values.unwrap()).unwrap(),
            Message::MsgFwdValues {
                agent_id: 50,
                peer_results: vec![
                    PeerResult::Reply(Packet {
                        message: message1,
                        msg_sig: None
                    }),
                    PeerResult::Unreachable(2),
                ]
            }
        );
    }
}
