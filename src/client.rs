use anyhow::{bail, Context};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::sync::{Arc, Mutex};
use text_colorizer::Colorize;
use tokio::io;
use tokio::net::TcpStream;
use tokio::spawn;

use crate::agent_config::AgentConfig;
use crate::keys::Keys;
use crate::message::Message;
use crate::network_utils::*;
use crate::packet::{Packet, PeerResult};

/// The outcome a relay reported for a specific peer it was asked to query on the client's
/// behalf, once its `PeerResult` has been authenticated (or found not to be authenticatable).
#[derive(Debug, Clone, Copy, PartialEq)]
enum PeerOutcome {
    /// The peer's value, extracted from a validly-signed `MsgSendValue`.
    Value(u64),
    /// The relay's claim that the peer could not be reached.
    Unreachable,
}

/// Represents a game client.
///
/// Clients are responsible for communicating with deployed agents
/// and querying for their individual values to determine the network value.
#[derive(Debug, Clone)]
pub struct Client {
    /// The client's Ed25519 key pair. Used for message authentication.
    keys: Keys,
    /// A vector containing information that allows the client to communicate with agents.
    peers: Vec<AgentConfig>,
    /// Tracks, per relay agent ID, the number of relay protocol violations detected across
    /// rounds played by this client (tampered replies, undeclared missing peers, or claims
    /// contradicted by another relay). Shared (not duplicated) across clones of `Client`, since
    /// each round clones `self` into an `Arc` for its concurrent per-peer tasks.
    relay_violations: Arc<Mutex<HashMap<usize, u32>>>,
}

impl Client {
    /// Returns a new instance of `Client` with a key pair for message signing
    /// and an empty `peers` Vec.
    pub fn new() -> Self {
        Client {
            keys: Keys::new_key_pair(),
            peers: Vec::new(),
            relay_violations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Records a relay protocol violation attributed to the relay agent identified by
    /// `relay_id`, incrementing its violation count.
    fn record_relay_violation(&self, relay_id: usize) {
        let mut violations = self.relay_violations.lock().unwrap();
        *violations.entry(relay_id).or_insert(0) += 1;
    }

    /// Returns the number of relay protocol violations recorded so far against the relay agent
    /// identified by `relay_id`.
    pub fn get_relay_violations(&self, relay_id: usize) -> u32 {
        let violations = self.relay_violations.lock().unwrap();
        *violations.get(&relay_id).unwrap_or(&0)
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

    /// Receives and processes the contents of `Message::MsgFwdValues`, sent by the relay agent
    /// identified by `relay_id`. Returns a `Vec<(usize, PeerOutcome)>` pairing each reported
    /// peer's `agent_id` with the outcome the relay claimed for it (a value, once its signature
    /// has been authenticated, or an unreachability claim). Returns `anyhow::Error` if the outer
    /// `MsgFwdValues` itself is unsigned or fails authentication.
    ///
    /// Any peer this client expected an answer for (i.e. every entry in `self.peers` other than
    /// the relay itself) that the relay's `peer_results` doesn't account for at all - neither a
    /// `Reply` nor an `Unreachable` claim - is recorded as a relay violation, since silently
    /// dropping a peer from the results entirely bypasses per-packet signature verification.
    fn handle_msg_fwd_values(
        &self,
        message_bytes: &[u8],
        signature: &Option<Vec<u8>>,
        peer_results: &Vec<PeerResult>,
        relay_id: usize,
        agent_pubkey: &str,
    ) -> anyhow::Result<Vec<(usize, PeerOutcome)>> {
        if let Some(signature) = signature {
            Keys::verify(message_bytes, signature, agent_pubkey)?;
        } else {
            bail!(
                "[!] error: MsgFwdValues requires a signature, but the received packet contains None\n"
            );
        }

        let mut outcomes: Vec<(usize, PeerOutcome)> = Vec::new();
        let mut covered_ids: HashSet<usize> = HashSet::new();

        for peer_result in peer_results {
            match peer_result {
                PeerResult::Reply(packet) => match Message::deserialize_message(&packet.message) {
                    Ok(Message::MsgSendValue { agent_id, value }) => {
                        covered_ids.insert(agent_id);
                        // Retrieve the public key of the agent who allegedly sent this MsgSendValue
                        if let Some(peer_pubkey) = self.get_agent_pubkey(agent_id) {
                            match Self::handle_msg_send_value(
                                &packet.message,
                                &packet.msg_sig,
                                &peer_pubkey,
                            ) {
                                // The received MsgSendValue was authenticated sucessfully
                                Ok(()) => outcomes.push((agent_id, PeerOutcome::Value(value))),
                                // Invalid signature: the relay tampered with the forwarded bytes
                                Err(_) => self.record_relay_violation(relay_id),
                            }
                        }
                    }
                    // If the forwarded message is not a MsgSendValue, ignore it
                    Ok(_) => (),
                    // The message could not be deserialized
                    // NOTE: It would be an improvement to log this and other similar types of errors
                    Err(_) => (),
                },
                PeerResult::Unreachable(agent_id) => {
                    covered_ids.insert(*agent_id);
                    outcomes.push((*agent_id, PeerOutcome::Unreachable));
                }
            }
        }

        for expected_peer in &self.peers {
            let expected_id = expected_peer.get_id();
            if expected_id != relay_id && !covered_ids.contains(&expected_id) {
                self.record_relay_violation(relay_id);
            }
        }

        Ok(outcomes)
    }

    /// Builds a `MsgFetchValues`, sends it to the agent at the other end of the `socket`
    /// TcpStream and expects a `MsgFwdValues` as a reply. Returns a `Vec<(usize, PeerOutcome)>`
    /// pairing each peer's `agent_id` with the outcome the relay reported for it, if successful,
    /// and `anyhow::Error` otherwise.
    async fn send_msg_fetch_values(
        client: Arc<Self>,
        socket: &mut TcpStream,
        agent_id: usize,
        agent_pubkey: &str,
    ) -> anyhow::Result<Vec<(usize, PeerOutcome)>> {
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
                agent_id,
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
    ///
    /// When more than one relay in `expert_subset` is asked about the same peer, their reports are
    /// cross-checked against each other before being counted: a relay's `Unreachable` claim for a
    /// peer that another relay reports a validly-signed `Value` for in the same round is a
    /// self-forgeable claim contradicted by a signature the contradicting relay cannot have
    /// forged, so it is flagged as a relay violation (see `Client::reconcile_reports`).
    pub async fn play_expert_round(
        &self,
        expert_subset: &Vec<AgentConfig>,
    ) -> anyhow::Result<Vec<u64>> {
        let mut agent_conn_handles = Vec::new();
        let client_arc = Arc::new(self.clone());

        // Maps each target agent_id to the (relay_id, outcome) reports received about it this
        // round, so reports about the same peer via different relay paths can be compared.
        let mut reports: HashMap<usize, Vec<(usize, PeerOutcome)>> = HashMap::new();

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
                let outcomes =
                    Self::send_msg_fetch_values(client, &mut socket, agent_id, &agent_pubkey)
                        .await;
                (agent_id, outcomes)
            });
            agent_conn_handles.push(handle);
        }

        for handle in agent_conn_handles {
            match handle.await {
                Ok((relay_id, Ok(outcomes))) => {
                    for (target_id, outcome) in outcomes {
                        reports
                            .entry(target_id)
                            .or_insert_with(Vec::new)
                            .push((relay_id, outcome));
                    }
                }
                Ok((_relay_id, Err(e))) => println!("{}", e),
                Err(e) => println!("[!] error: task panicked - {}\n", e),
            }
        }

        self.reconcile_reports(&reports);

        let agent_values = Self::extract_unique_values(&reports);
        let agent_values: Vec<u64> = agent_values.iter().map(|&(_, value)| value).collect();

        Ok(agent_values)
    }

    /// Cross-checks this round's reports for each target peer. A relay's own value can't be
    /// forged (it carries the peer's Ed25519 signature), so a peer that produced a validly-signed
    /// `Value` report through one relay was demonstrably reachable in this round - any other
    /// relay that reported the same peer as `Unreachable` is therefore caught in a falsifiable,
    /// attributable claim and is recorded as a relay violation.
    ///
    /// This only detects contradictions when a peer is reported on by more than one relay in
    /// `expert_subset`; it does not provide Byzantine-fault-tolerant guarantees against a
    /// colluding majority of relays agreeing on the same false claim.
    fn reconcile_reports(&self, reports: &HashMap<usize, Vec<(usize, PeerOutcome)>>) {
        for reported in reports.values() {
            let has_value = reported
                .iter()
                .any(|(_, outcome)| matches!(outcome, PeerOutcome::Value(_)));
            if !has_value {
                continue;
            }
            for (relay_id, outcome) in reported {
                if *outcome == PeerOutcome::Unreachable {
                    self.record_relay_violation(*relay_id);
                }
            }
        }
    }

    /// Extracts a deduplicated set of (agent_id, value) pairs from this round's reports.
    fn extract_unique_values(
        reports: &HashMap<usize, Vec<(usize, PeerOutcome)>>,
    ) -> HashSet<(usize, u64)> {
        let mut values = HashSet::new();
        for (&target_id, reported) in reports {
            for (_, outcome) in reported {
                if let PeerOutcome::Value(value) = outcome {
                    values.insert((target_id, *value));
                }
            }
        }
        values
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
    use std::time::Duration;
    use tokio::net::TcpListener;

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

    #[test]
    fn test_handle_msg_fwd_values_flags_undeclared_missing_peer() {
        let mut client = Client::new();
        let peer_a_keys = Keys::new_key_pair();
        let peer_b_keys = Keys::new_key_pair();
        let relay_keys = Keys::new_key_pair();

        client.peers = vec![
            AgentConfig::new(1, "127.0.0.1", 9001, peer_a_keys.get_public_key()),
            AgentConfig::new(2, "127.0.0.1", 9002, peer_b_keys.get_public_key()),
        ];

        let relay_id = 99;

        // The relay only accounts for peer 1 (neither a Reply nor an Unreachable claim is given
        // for peer 2), which should be flagged as a violation.
        let value_message = Message::build_msg_send_value(42, 1).unwrap();
        let value_sig = peer_a_keys.sign(&value_message).unwrap();
        let peer_results = vec![PeerResult::Reply(Packet::new(value_message, Some(value_sig)))];

        let fwd_message = Message::build_msg_fwd_values(relay_id, &peer_results).unwrap();
        let fwd_sig = relay_keys.sign(&fwd_message).unwrap();

        let outcomes = client
            .handle_msg_fwd_values(
                &fwd_message,
                &Some(fwd_sig),
                &peer_results,
                relay_id,
                relay_keys.get_public_key(),
            )
            .unwrap();

        assert_eq!(outcomes, vec![(1, PeerOutcome::Value(42))]);
        assert_eq!(client.get_relay_violations(relay_id), 1);
    }

    #[test]
    fn test_handle_msg_fwd_values_no_violation_when_fully_accounted() {
        let mut client = Client::new();
        let peer_a_keys = Keys::new_key_pair();
        let relay_keys = Keys::new_key_pair();

        client.peers = vec![AgentConfig::new(
            1,
            "127.0.0.1",
            9001,
            peer_a_keys.get_public_key(),
        )];

        let relay_id = 99;
        let peer_results = vec![PeerResult::Unreachable(1)];

        let fwd_message = Message::build_msg_fwd_values(relay_id, &peer_results).unwrap();
        let fwd_sig = relay_keys.sign(&fwd_message).unwrap();

        let outcomes = client
            .handle_msg_fwd_values(
                &fwd_message,
                &Some(fwd_sig),
                &peer_results,
                relay_id,
                relay_keys.get_public_key(),
            )
            .unwrap();

        assert_eq!(outcomes, vec![(1, PeerOutcome::Unreachable)]);
        assert_eq!(client.get_relay_violations(relay_id), 0);
    }

    // Test that handle_msg_fwd_values accumulates multiple valid Reply entries from different
    // peers independently, and that one entry with a bad signature (tampered content) is dropped
    // and flagged without affecting the other, validly-signed entries in the same batch. This is
    // the multi-peer forwarding loop a relay exercises in normal operation (most peers honest and
    // reachable), which the single-Reply tests above don't cover on their own.
    #[test]
    fn test_handle_msg_fwd_values_accumulates_multiple_replies_independently() {
        let mut client = Client::new();
        let peer_a_keys = Keys::new_key_pair();
        let peer_b_keys = Keys::new_key_pair();
        let peer_c_keys = Keys::new_key_pair();
        let relay_keys = Keys::new_key_pair();

        client.peers = vec![
            AgentConfig::new(1, "127.0.0.1", 9001, peer_a_keys.get_public_key()),
            AgentConfig::new(2, "127.0.0.1", 9002, peer_b_keys.get_public_key()),
            AgentConfig::new(3, "127.0.0.1", 9003, peer_c_keys.get_public_key()),
        ];

        let relay_id = 99;

        let value_a = Message::build_msg_send_value(10, 1).unwrap();
        let sig_a = peer_a_keys.sign(&value_a).unwrap();

        let value_b = Message::build_msg_send_value(20, 2).unwrap();
        let sig_b = peer_b_keys.sign(&value_b).unwrap();

        // Peer 3's signature was produced for a different value than what's actually forwarded,
        // simulating a relay that tampered with this one entry.
        let value_c = Message::build_msg_send_value(30, 3).unwrap();
        let sig_c = peer_c_keys.sign(&value_c).unwrap();
        let tampered_value_c = Message::build_msg_send_value(99, 3).unwrap();

        let peer_results = vec![
            PeerResult::Reply(Packet::new(value_a, Some(sig_a))),
            PeerResult::Reply(Packet::new(value_b, Some(sig_b))),
            PeerResult::Reply(Packet::new(tampered_value_c, Some(sig_c))),
        ];

        let fwd_message = Message::build_msg_fwd_values(relay_id, &peer_results).unwrap();
        let fwd_sig = relay_keys.sign(&fwd_message).unwrap();

        let outcomes = client
            .handle_msg_fwd_values(
                &fwd_message,
                &Some(fwd_sig),
                &peer_results,
                relay_id,
                relay_keys.get_public_key(),
            )
            .unwrap();

        assert_eq!(
            outcomes,
            vec![(1, PeerOutcome::Value(10)), (2, PeerOutcome::Value(20))]
        );
        // Peer 3's tampered entry fails signature verification and is recorded as a violation,
        // but doesn't prevent peers 1 and 2's valid entries from being accumulated above.
        assert_eq!(client.get_relay_violations(relay_id), 1);
    }

    #[test]
    fn test_reconcile_reports_flags_contradicted_unreachable_claim() {
        let client = Client::new();

        let mut reports: HashMap<usize, Vec<(usize, PeerOutcome)>> = HashMap::new();
        // Relay 10 vouches for peer 5 with a value; relay 20 claims peer 5 is unreachable in the
        // same round - relay 20's claim is falsified by relay 10's unforgeable signed value.
        reports.insert(
            5,
            vec![(10, PeerOutcome::Value(7)), (20, PeerOutcome::Unreachable)],
        );

        client.reconcile_reports(&reports);

        assert_eq!(client.get_relay_violations(20), 1);
        assert_eq!(client.get_relay_violations(10), 0);
    }

    #[test]
    fn test_reconcile_reports_no_violation_without_contradiction() {
        let client = Client::new();

        let mut reports: HashMap<usize, Vec<(usize, PeerOutcome)>> = HashMap::new();
        // Both relays agree the peer is unreachable - no signed value contradicts this claim.
        reports.insert(
            5,
            vec![(10, PeerOutcome::Unreachable), (20, PeerOutcome::Unreachable)],
        );

        client.reconcile_reports(&reports);

        assert_eq!(client.get_relay_violations(10), 0);
        assert_eq!(client.get_relay_violations(20), 0);
    }

    #[test]
    fn test_extract_unique_values_ok() {
        let mut reports: HashMap<usize, Vec<(usize, PeerOutcome)>> = HashMap::new();
        reports.insert(
            1,
            vec![(10, PeerOutcome::Value(5)), (11, PeerOutcome::Value(5))],
        );
        reports.insert(2, vec![(10, PeerOutcome::Unreachable)]);

        let values = Client::extract_unique_values(&reports);
        assert_eq!(values, HashSet::from([(1, 5)]));
    }

    // Test that play_expert_round, driven end-to-end over real TCP sockets against two fake
    // relay agents, both recovers a contested peer's real value and flags the relay that falsely
    // denied it - exercising the same reconciliation behavior as
    // test_reconcile_reports_flags_contradicted_unreachable_claim above, but through the actual
    // public seam (play_expert_round's return value and get_relay_violations) rather than
    // reconcile_reports/extract_unique_values directly, so this test survives a refactor of how
    // reports are accumulated internally.
    #[tokio::test]
    async fn test_play_expert_round_detects_contradicted_unreachable_claim_via_sockets() {
        let mut client = Client::new();

        let peer_keys = Keys::new_key_pair();
        let honest_relay_keys = Keys::new_key_pair();
        let lying_relay_keys = Keys::new_key_pair();

        let peer_id = 5;
        let honest_relay_id = 10;
        let lying_relay_id = 20;

        let honest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let honest_addr = honest_listener.local_addr().unwrap();

        let lying_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lying_addr = lying_listener.local_addr().unwrap();

        // Only the contested peer needs to be registered here: it's what `client.peers` is sent
        // to relays as (the set they're asked to report on) and where inner `Reply` signatures
        // are verified against. The relays' own pubkeys are supplied via `expert_subset` below.
        client.peers = vec![AgentConfig::new(
            peer_id,
            "127.0.0.1",
            9000,
            peer_keys.get_public_key(),
        )];

        let expert_subset = vec![
            AgentConfig::new(
                honest_relay_id,
                "127.0.0.1",
                honest_addr.port() as usize,
                honest_relay_keys.get_public_key(),
            ),
            AgentConfig::new(
                lying_relay_id,
                "127.0.0.1",
                lying_addr.port() as usize,
                lying_relay_keys.get_public_key(),
            ),
        ];

        // Honest relay: replies with the peer's real, validly-signed value.
        let honest_task = tokio::spawn(async move {
            let (mut socket, _) = honest_listener.accept().await.unwrap();
            let _request = tokio::time::timeout(Duration::from_secs(5), recv_packet(&mut socket))
                .await
                .unwrap()
                .unwrap();

            let value_message = Message::build_msg_send_value(7, peer_id).unwrap();
            let value_sig = peer_keys.sign(&value_message).unwrap();
            let peer_results = vec![PeerResult::Reply(Packet::new(value_message, Some(value_sig)))];

            let fwd_message =
                Message::build_msg_fwd_values(honest_relay_id, &peer_results).unwrap();
            let fwd_sig = honest_relay_keys.sign(&fwd_message).unwrap();
            let packet_bytes = Packet::build_packet(fwd_message, Some(fwd_sig)).unwrap();

            send_packet(&packet_bytes, &mut socket).await.unwrap();
        });

        // Lying relay: falsely claims the same peer is unreachable, even though it's live.
        let lying_task = tokio::spawn(async move {
            let (mut socket, _) = lying_listener.accept().await.unwrap();
            let _request = tokio::time::timeout(Duration::from_secs(5), recv_packet(&mut socket))
                .await
                .unwrap()
                .unwrap();

            let peer_results = vec![PeerResult::Unreachable(peer_id)];
            let fwd_message = Message::build_msg_fwd_values(lying_relay_id, &peer_results).unwrap();
            let fwd_sig = lying_relay_keys.sign(&fwd_message).unwrap();
            let packet_bytes = Packet::build_packet(fwd_message, Some(fwd_sig)).unwrap();

            send_packet(&packet_bytes, &mut socket).await.unwrap();
        });

        let agent_values = client.play_expert_round(&expert_subset).await.unwrap();

        honest_task.await.unwrap();
        lying_task.await.unwrap();

        assert_eq!(agent_values, vec![7]);
        assert_eq!(client.get_relay_violations(lying_relay_id), 1);
        assert_eq!(client.get_relay_violations(honest_relay_id), 0);
    }
}
