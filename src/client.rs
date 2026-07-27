use anyhow::{bail, Context};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use text_colorizer::Colorize;
use tokio::io;
use tokio::net::TcpStream;
use tokio::spawn;

use crate::agent_config::AgentConfig;
use crate::keys::Keys;
use crate::message::Message;
use crate::network_utils::*;
use crate::packet::{Packet, PeerResult};

/// Represents a game client.
///
/// Clients are responsible for communicating with deployed agents
/// and querying for their individual values to determine the network value.
#[derive(Debug, PartialEq, Clone)]
pub struct Client {
    /// The client's Ed25519 key pair. Used for message authentication.
    keys: Keys,
    /// A vector containing information that allows the client to communicate with agents.
    peers: Vec<AgentConfig>,
}

impl Client {
    /// Returns a new instance of `Client` with a key pair for message signing
    /// and an empty `peers` Vec.
    pub fn new() -> Self {
        Client {
            keys: Keys::new_key_pair(),
            peers: Vec::new(),
        }
    }

    /// Returns the client's keypair for message signing.
    pub fn get_keys(&self) -> &Keys {
        &self.keys
    }

    /// Returns the client's list of peers.
    pub fn get_peers(&self) -> &Vec<AgentConfig> {
        &self.peers
    }

    /// Attempts to read the `AgentConfig` data from the `agents.config` file
    /// and return it if the read operation succeeds.
    pub fn read_agent_config() -> Result<String, io::Error> {
        let config = fs::read_to_string("agents.config")?;
        Ok(config)
    }

    /// Receives a string slice containing the data read from `agents.config`
    /// and attempts to deserialize and store it in Client.peers
    pub fn store_agent_config(&mut self, agent_config: &str) -> Result<(), serde_json::Error> {
        self.peers = serde_json::from_str(&agent_config)?;
        Ok(())
    }

    /// Reads agent configuration from a file and stores it in an instance of `Client`.
    pub fn load_agent_config(&mut self) -> anyhow::Result<()> {
        let agent_config = Self::read_agent_config()?;
        self.store_agent_config(&agent_config)?;
        Ok(())
    }

    /// Receives a `MsgSendValue` from an agent and verifies if it has been correctly signed by the
    /// agent to whom the client has sent a `MsgQueryValue`.
    fn handle_msg_send_value(
        message_bytes: &[u8],
        signature: &Option<Vec<u8>>,
        public_key: &str,
    ) -> anyhow::Result<()> {
        if let Some(signature) = signature {
            Keys::verify(message_bytes, signature, public_key)?;
        } else {
            bail!(
                "[!] error: MsgSendValue requires a signature, but the received packet contains None\n"
            );
        }
        Ok(())
    }

    /// Receives `agent_id` and searches `Client.peers` for an agent with ID equal to `agent_id`.
    /// If found, returns the agent's base64-encoded public key, otherwise returns None.
    fn get_agent_pubkey(&self, agent_id: usize) -> Option<String> {
        self.peers
            .iter()
            .find(|agent| agent.get_id() == agent_id)
            .map(|agent| agent.get_public_key().to_string())
    }

    /// Receives the values reported by the game's agents and infers the network value from them.
    /// If multiple values are tied with the most occurrences, return all of them.
    ///
    /// For example, given the values below, both 2 and 8 will be returned as the network value.
    ///     Number 2: 4 votes
    ///     Number 5: 1 vote  
    ///     Number 8: 4 votes
    ///     
    pub fn infer_network_value(agent_values: &Vec<u64>) -> Option<Vec<u64>> {
        let mut values_count = HashMap::new();

        // Count the number of occurrences of each different value returned by the agents
        for &value in agent_values {
            *values_count.entry(value).or_insert(0) += 1;
        }

        // Return the maximum number of occurrences out of all the values
        let max_count = match values_count.values().max() {
            Some(max_count) => *max_count,
            None => return None,
        };

        // Get all the values whose occurrence is equal to the max number of occurrences.
        // Different values may be tied with the most number of occurrences, in which case
        // all of them will be returned as the network value.
        let network_value = values_count
            .into_iter()
            .filter(|&(_, value_count)| value_count == max_count)
            .map(|(value, _)| value)
            .collect();

        Some(network_value)
    }

    /// Prints the network value inferred after playing a round of the game. Will print
    /// multiple values if there was no majority consensus on a single network value.
    pub fn print_network_value(network_value: &Option<Vec<u64>>) {
        match network_value {
            Some(network_value) => match network_value.len() {
                // If a single value has the majority of votes
                1 => println!(
                    "{} {}\n",
                    "[+] The network value is:".bold(),
                    network_value[0]
                ),

                // If different values are tied for the majority of votes
                _ => {
                    let values: Vec<String> = network_value
                        .iter()
                        .map(|value| value.to_string())
                        .collect();

                    println!(
                        "{}",
                        "[+] Unable to determine a single network value.".bold()
                    );
                    println!(
                        "{} {}\n",
                        "[+] The following values are tied:".bold(),
                        values.join(", ")
                    );
                }
            },

            // If no valid votes were received from the agents
            None => {
                println!(
                    "{}",
                    "[+] Unable to determine the network value; no valid replies were received.\n"
                        .bold()
                );
            }
        }
    }

    /// Queries an individual agent for its value by sending a `MsgQueryValue`. Returns the agent's
    /// value as u64 if successful and `anyhow::Error` otherwise.
    async fn send_msg_query_value(
        client: Arc<Self>,
        socket: &mut TcpStream,
        agent_pubkey: &str,
    ) -> anyhow::Result<u64> {
        let message = Message::build_msg_query_value()
            .context("[!] error: failed to build MsgQueryValue\n")?;

        // Compute the signature of the serialized message
        // NOTE: For messages composed by large amounts of data, signing the whole message incurs
        // a significant overhead. Ideally, the hash of  the message should be signed instead.
        // Here, given the small sizes of messages, we sign the whole message for simplicity's sake.
        let message_signature = client.keys.sign(&message)?;

        // Build a packet with the message and message signature
        let packet = Packet::build_packet(message, Some(message_signature))
            .context("[!] error: failed to build packet\n")?;

        match send_packet(&packet, socket).await {
            Ok(()) => (),
            Err(e) => bail!("[!] error: unable to reach agent - {}", e),
        }

        let reply = recv_packet(socket).await?;
        let reply_packet = Packet::unpack(&reply)?;

        match Message::deserialize_message(&reply_packet.message) {
            Ok(Message::MsgSendValue { value, .. }) => {
                match Self::handle_msg_send_value(
                    &reply_packet.message,
                    &reply_packet.msg_sig,
                    agent_pubkey,
                ) {
                    Ok(()) => Ok(value),
                    Err(e) => Err(e),
                }
            }
            Ok(other) => bail!("[!] error: expected MsgSendValue, received {:?}\n", other),
            Err(e) => bail!("[!] error: unable to decode message - {}\n", e),
        }
    }

    /// Builds and sends a MsgKillAgent to an active agent. This message does not expect a reply.
    async fn send_msg_kill_agent(
        client: &Self,
        agent_id: usize,
        socket: &mut TcpStream,
    ) -> anyhow::Result<()> {
        let message = Message::build_msg_kill_agent(agent_id)
            .context("[!] error: failed to build MsgKillAgent\n")?;

        let message_signature = client.keys.sign(&message)?;

        let packet = Packet::build_packet(message, Some(message_signature))
            .context("[!] error: failed to build packet\n")?;

        match send_packet(&packet, socket).await {
            Ok(()) => Ok(()),
            Err(e) => bail!("[!] error: unable to reach agent {} - {}", agent_id, e),
        }
    }

    /// Receives and processes the contents of `Message::MsgFwdValues`. Returns a `Vec<Message>`
    /// containing all the valid/authenticated messages extracted from `MsgFwdValues` and
    /// `anyhow::Error` otherwise.
    ///
    /// NOTE: a relay now reports one `PeerResult` per requested peer instead of simply omitting
    /// peers it doesn't want the client to hear from, so a peer's absence from the wire format is
    /// no longer possible without an explicit (if unsigned) `Unreachable` claim. This method does
    /// not yet cross-check `Unreachable` claims against other relays or hold relays accountable
    /// for omissions/contradictions - see follow-up work.
    fn handle_msg_fwd_values(
        &self,
        message_bytes: &[u8],
        signature: &Option<Vec<u8>>,
        peer_results: &Vec<PeerResult>,
        agent_pubkey: &str,
    ) -> anyhow::Result<Vec<Message>> {
        if let Some(signature) = signature {
            Keys::verify(message_bytes, signature, agent_pubkey)?;
        } else {
            bail!(
                "[!] error: MsgFwdValues requires a signature, but the received packet contains None\n"
            );
        }

        let mut received_messages: Vec<Message> = Vec::new();

        for peer_result in peer_results {
            let packet = match peer_result {
                PeerResult::Reply(packet) => packet,
                // Not yet acted upon; see NOTE above.
                PeerResult::Unreachable(_) => continue,
            };

            match Message::deserialize_message(&packet.message) {
                Ok(Message::MsgSendValue { agent_id, value }) => {
                    // Retrieve the public key of the agent who sent this `MsgSendValue`
                    if let Some(agent_pubkey) = self.get_agent_pubkey(agent_id) {
                        match Self::handle_msg_send_value(
                            &packet.message,
                            &packet.msg_sig,
                            &agent_pubkey,
                        ) {
                            // The received MsgSendValue was authenticated sucessfully
                            Ok(()) => {
                                received_messages.push(Message::MsgSendValue { agent_id, value })
                            }
                            // If the signature of the MsgSendValue is invalid, ignore the value
                            Err(_) => (),
                        }
                    }
                }
                // If the forwarded message is not a MsgSendValue, ignore it
                Ok(_) => (),
                // The message could not be deserialized
                // NOTE: It would be an improvement to log this and other similar types of errors
                Err(_) => (),
            }
        }
        Ok(received_messages)
    }

    /// Builds a `MsgFetchValues`, sends it to the agent at the other end of the `socket`
    /// TcpStream and expects a `MsgFwdValues` as a reply. Returns a `Vec<Message>` containing the
    /// messages forwarded by the agent if successful and `anyhow::Error` otherwise.
    async fn send_msg_fetch_values(
        client: Arc<Self>,
        socket: &mut TcpStream,
        agent_id: usize,
        agent_pubkey: &str,
    ) -> anyhow::Result<Vec<Message>> {
        let message = Message::build_msg_fetch_values(agent_id, &client.peers)
            .context("[!] error: failed to build MsgFetchValues\n")?;

        let message_signature = client.keys.sign(&message)?;

        let packet = Packet::build_packet(message, Some(message_signature))
            .context("[!] error: failed to build packet\n")?;

        match send_packet(&packet, socket).await {
            Ok(()) => (),
            Err(e) => bail!("[!] error: unable to reach agent {} - {}", agent_id, e),
        }

        let reply = recv_packet(socket).await?;
        let reply_packet = Packet::unpack(&reply)?;

        match Message::deserialize_message(&reply_packet.message) {
            Ok(Message::MsgFwdValues { peer_results, .. }) => client.handle_msg_fwd_values(
                &reply_packet.message,
                &reply_packet.msg_sig,
                &peer_results,
                agent_pubkey,
            ),
            Ok(other) => bail!("[!] error: expected MsgFwdValues, received {:?}\n", other),
            Err(e) => bail!("[!] error: unable to decode message - {}\n", e),
        }
    }

    /// Plays a standard round of the game. The game's client connects to the agents loaded
    /// from the `agents.config` file, queries them individually for their values and
    /// returns a Vec<u64> containing all valid agent replies. A reply is valid iff
    /// the received message is not corrupted and it has been signed by the agent to which
    /// the query was sent.
    pub async fn play_standard_round(&self) -> anyhow::Result<Vec<u64>> {
        let mut agent_conn_handles = Vec::new();
        let mut agent_values = Vec::new();
        let client_arc = Arc::new(self.clone());

        for peer in &self.peers {
            let address = peer.get_address();
            let port = peer.get_port();
            let mut socket = match connect(address, port).await {
                Ok(socket) => socket,
                Err(e) => {
                    println!(
                        "[!] error: failed to connect to (Agent ID: {} - {}:{}) - {}\n",
                        peer.get_id(),
                        address,
                        port,
                        e
                    );
                    continue;
                }
            };

            let agent_pubkey = peer.get_public_key().to_owned();
            let client = client_arc.clone();
            let handle = spawn(async move {
                Self::send_msg_query_value(client, &mut socket, &agent_pubkey).await
            });
            agent_conn_handles.push(handle);
        }

        for handle in agent_conn_handles {
            match handle.await {
                Ok(Ok(agent_value)) => {
                    agent_values.push(agent_value);
                }
                Ok(Err(e)) => println!("{}", e),
                Err(e) => println!("[!] error: task panicked - {}\n", e),
            }
        }

        Ok(agent_values)
    }

    /// Plays an expert round of the game. The game's client connects to a subset of the agents
    /// loaded from the `agents.config` file and queries them for both their values and the values of
    /// other agents that are not in the subset and cannot be reached directly. This function returns
    /// a `Vec<u64>` containing all the valid unique values received from agents. A message containing
    /// a value is only valid if the client can verify that it was signed by the sending agent.
    pub async fn play_expert_round(
        &self,
        expert_subset: &Vec<AgentConfig>,
    ) -> anyhow::Result<Vec<u64>> {
        let mut agent_conn_handles = Vec::new();
        let client_arc = Arc::new(self.clone());

        let mut agent_values: HashSet<(usize, u64)> = HashSet::new();

        for peer in expert_subset {
            let address = peer.get_address();
            let port = peer.get_port();
            let mut socket = match connect(address, port).await {
                Ok(socket) => socket,
                Err(e) => {
                    println!(
                        "[!] error: failed to connect to (Agent ID: {} - {}:{}) - {}\n",
                        peer.get_id(),
                        address,
                        port,
                        e
                    );
                    continue;
                }
            };

            let client = client_arc.clone();
            let agent_pubkey = peer.get_public_key().to_owned();
            let agent_id = peer.get_id();
            let handle = spawn(async move {
                Self::send_msg_fetch_values(client, &mut socket, agent_id, &agent_pubkey).await
            });
            agent_conn_handles.push(handle);
        }

        for handle in agent_conn_handles {
            match handle.await {
                Ok(Ok(fetched_messages)) => {
                    // Keep only the previously unknown values contained in the `MsgFwdValues`
                    Self::filter_unique_values(&mut agent_values, &fetched_messages)
                }
                Ok(Err(e)) => println!("{}", e),
                Err(e) => println!("[!] error: task panicked - {}\n", e),
            }
        }

        let agent_values: Vec<u64> = agent_values.iter().map(|&(_, value)| value).collect();

        Ok(agent_values)
    }

    /// Receives a vector of messages `&Vec<Message>`, extracts all `MsgSendValue` it contains and
    /// uses a HashSet to store only the tuples (agent_id, value) which were not yet known.
    fn filter_unique_values(received_values: &mut HashSet<(usize, u64)>, messages: &Vec<Message>) {
        for message in messages {
            match message {
                Message::MsgSendValue { agent_id, value } => {
                    let _ = received_values.insert((*agent_id, *value));
                }
                _ => (),
            }
        }
    }

    /// Connects to `address`:`port` and sends a `MsgKillAgent` addressed to `agent_id`.
    pub async fn kill_agent(
        &self,
        agent_id: usize,
        address: &str,
        port: usize,
    ) -> anyhow::Result<String> {
        let mut socket = match connect(address, port).await {
            Ok(socket) => socket,
            Err(e) => {
                bail!(
                    "[!] error: failed to connect to {}:{} - {}\n",
                    address,
                    port,
                    e
                )
            }
        };

        let client = self.clone();
        let handle =
            spawn(async move { Self::send_msg_kill_agent(&client, agent_id, &mut socket).await });

        match handle.await {
            Ok(Ok(())) => Ok(format!(
                "{} (Agent ID: {} - {}:{})\n",
                "[+] Killed agent".bold(),
                agent_id,
                address,
                port
            )),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e.into()),
        }
    }
}

// ******************************************************************************************
// ************************************* UNIT TESTS *****************************************
// ******************************************************************************************

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_agent_config_ok() {
        let mut client = Client::new();

        let agent_config = r#"
        [
            {
                "agent_id": 1,
                "address": "127.0.0.1",
                "port": 5000,
                "public_key": "1gVlq8XFG6qQ+4qj5GvX2xQZVc2bTlMVslNV6z8fuBI="
            },
            {
                "agent_id": 2,
                "address": "127.0.0.1",
                "port": 5001,
                "public_key": "b8CZcEFBzcGqWqP4G+QjiKsXjOsCOyowNdIxfmfg+54="
            }
        ]
        "#
        .to_owned();

        assert!(client.store_agent_config(&agent_config).is_ok());

        assert_eq!(
            client.get_peers().clone(),
            vec![
                AgentConfig::new(
                    1,
                    "127.0.0.1",
                    5000,
                    "1gVlq8XFG6qQ+4qj5GvX2xQZVc2bTlMVslNV6z8fuBI="
                ),
                AgentConfig::new(
                    2,
                    "127.0.0.1",
                    5001,
                    "b8CZcEFBzcGqWqP4G+QjiKsXjOsCOyowNdIxfmfg+54="
                )
            ]
        );
    }

    #[test]
    fn test_infer_network_value_ok() {
        // A single network value should be returned
        let agent_values = vec![1, 1, 2, 3, 4, 5, 6, 7];
        let mut network_values = Client::infer_network_value(&agent_values).unwrap();
        network_values.sort();
        assert_eq!(network_values, vec![1]);

        // Two network values should be returned
        let agent_values = vec![1, 1, 2, 3, 4, 4, 5, 6, 7];
        let mut network_values = Client::infer_network_value(&agent_values).unwrap();
        network_values.sort();
        assert_eq!(network_values, vec![1, 4]);

        // Multiple network values should be returned
        let agent_values = vec![1, 2, 3, 4, 5, 6, 7];
        let mut network_values = Client::infer_network_value(&agent_values).unwrap();
        network_values.sort();
        assert_eq!(network_values, vec![1, 2, 3, 4, 5, 6, 7]);

        // Should return `None`
        let agent_values = vec![];
        let network_values = Client::infer_network_value(&agent_values);
        assert!(network_values.is_none());
    }
}
