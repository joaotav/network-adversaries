use anyhow::{bail, Context};
use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use text_colorizer::Colorize;
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::agent_config::AgentConfig;
use crate::keys::Keys;
use crate::message::Message;
use crate::network_utils::*;
use crate::packet::{Packet, PeerResult};

static AGENT_ID_COUNTER: AtomicUsize = AtomicUsize::new(1);
static BASE_PORT: AtomicUsize = AtomicUsize::new(5_000);
const AGENT_ADDR: &str = "127.0.0.1";

/// Represents an agent in the Liars Lie game.
///
/// Each `Agent` has an unique identifier `agent_id`, a value `value` to report when
/// queried, and a network `address` and `port` used for communication with clients and
/// other Agents. Agents can be instantiated as either honest or liars.
#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    /// An identifier for each instance of Agent.
    agent_id: usize,
    /// A value to be reported by the agent when queried.
    value: u64,
    /// The network address in which the agent listens when deployed.
    address: String,
    /// The network port in which the agent listens when deployed.
    port: usize,
    /// The agent's private and public keys for signing messages.
    keys: Keys,
    /// The game client's base64-encoded public key. Used to authenticate received messages.
    game_client_pubkey: String,
    /// A flag to indicate whether this agent has been deployed or not.
    status: AgentStatus,
    /// A flag to indicate whether this agent is a liar or not.
    is_liar: bool,
    /// The probability that the agent will tamper with messages when forwarding them
    tamper_chance: f32,
}

#[derive(PartialEq, Clone, Debug, Copy)]
pub enum AgentStatus {
    Uninitialized,
    Ready,
    Killed,
}

impl Agent {
    /// Returns a new honest instance of `Agent` with the `value` field set to the value
    /// received as argument. Each new instance is assigned an unique `agent_id`
    /// and `port`.
    pub fn new_honest(value: u64, game_client_pubkey: String) -> Self {
        let agent_id = Self::get_new_id();
        let address = AGENT_ADDR.to_owned();
        let port = Self::get_new_port();
        let keys = Keys::new_key_pair();
        let status = AgentStatus::Uninitialized;
        let is_liar = false;
        let tamper_chance = 0.0;
        Agent {
            agent_id,
            value,
            address,
            port,
            keys,
            game_client_pubkey,
            status,
            is_liar,
            tamper_chance,
        }
    }

    /// Returns a new liar instance of `Agent` with the `value` field set to an arbitrary
    /// value x, such that x != honest_value AND 1 <= x <= max_value. Each new instance
    /// is assigned an unique `agent_id` and `port`.
    pub fn new_liar(
        honest_value: u64,
        max_value: u64,
        game_client_pubkey: String,
        tamper_chance: f32,
    ) -> Self {
        let agent_id = Self::get_new_id();
        let value = Self::get_liar_value(honest_value, max_value);
        let address = AGENT_ADDR.to_owned();
        let port = Self::get_new_port();
        let keys = Keys::new_key_pair();
        let status = AgentStatus::Uninitialized;
        let is_liar = true;
        Agent {
            agent_id,
            value,
            address,
            port,
            keys,
            game_client_pubkey,
            status,
            is_liar,
            tamper_chance,
        }
    }

    /// Gets an agent's status. Returns `true` the agent has been spawned and `false` otherwise.
    pub fn get_status(&self) -> AgentStatus {
        self.status
    }

    /// Returns an agent's unique ID.
    pub fn get_id(&self) -> usize {
        self.agent_id
    }

    /// Returns an agent's network address.
    pub fn get_address(&self) -> &str {
        &self.address
    }

    /// Returns the port at which an agent is listening on `Agent.address`.
    pub fn get_port(&self) -> usize {
        self.port
    }

    /// Sets an agent's status ready. Used to indicate whether or not the agent has been spawned.
    pub fn set_ready(&mut self) {
        self.status = AgentStatus::Ready
    }

    /// Sets an agent's status to `Killed` to indicate that it is inactive but should not be spawned.
    pub fn set_killed(&mut self) {
        self.status = AgentStatus::Killed
    }

    /// Returns a bool indicating whether the agent is a liar or not.
    pub fn is_liar(&self) -> bool {
        self.is_liar
    }

    /// Receives an instance of `Agent` to generate a new instance of `AgentConfig`,
    /// which contains only the fields of `Agent` that can be shared with other
    /// participants of the game.
    pub fn to_config(&self) -> AgentConfig {
        AgentConfig::new(
            self.agent_id,
            &self.address,
            self.port,
            &self.keys.get_public_key(),
        )
    }

    /// Receives a `Vec<PeerResult>` containing the results to be forwarded to the game's client
    /// and tampers with them with a probability equal to `Agent.tamper_chance`. Each `Reply` that
    /// is chosen for tampering is either corrupted in place (detectable by the client via
    /// signature verification) or suppressed entirely by relabeling it as `Unreachable` (not tied
    /// to any signature, so it can only be caught by the client cross-checking this relay's
    /// report against other relays' reports for the same peer).
    fn tamper_with_messages(&self, peer_results: &mut [PeerResult]) -> Result<(), bincode::Error> {
        // For `tamper_chance` == 0.05, the probability of tampering wih any given message is 5%.
        let tamper_chance = (self.tamper_chance * 100.0) as i32;

        for peer_result in peer_results.iter_mut() {
            let tamper_roll = rand::thread_rng().gen_range(0..=(100));
            if tamper_roll > tamper_chance {
                continue;
            }

            if let PeerResult::Reply(packet) = peer_result {
                if rand::thread_rng().gen_bool(0.5) {
                    // Change the message contained within the packet to an arbitrary message.
                    packet.message =
                        Message::build_msg_send_value(tamper_roll as u64, tamper_roll as usize)?;
                } else if let Message::MsgSendValue { agent_id, .. } =
                    Message::deserialize_message(&packet.message)?
                {
                    *peer_result = PeerResult::Unreachable(agent_id);
                }
            }
        }
        Ok(())
    }

    /// Builds and sends a `MsgSendValue` packet as a response to a `MsgQueryValue` request.
    async fn handle_msg_query_value(&self, socket: &mut TcpStream) -> anyhow::Result<()> {
        // Build a MsgSendValue to send as a reply to MsgQueryValue
        let reply = Message::build_msg_send_value(self.value, self.agent_id)?;

        // Generate a signature of the message
        let reply_sig = self.keys.sign(&reply)?;

        // Build a packet containing the message and the message signature
        let reply_packet = Packet::build_packet(reply, Some(reply_sig))?;

        send_packet(&reply_packet, socket).await?;

        Ok(())
    }

    /// Receives a MsgKillAgent, verifies the intendend recipient against self and verifies the
    /// message signature. Returns Ok(()) if the agent should be killed.
    fn handle_msg_kill_agent(
        &self,
        message_bytes: &[u8],
        signature: &Option<Vec<u8>>,
        agent_id: usize,
    ) -> anyhow::Result<()> {
        // If the received message is accompanied by a signature and is addressed to this agent,
        // verify if the signature was generated by the game client.
        if let Some(signature) = signature {
            if agent_id == self.agent_id {
                Keys::verify(message_bytes, signature, &self.game_client_pubkey)?;
            } else {
                bail!("[!] error: MsgKillAgent was intended for a different recipient\n")
            }
        } else {
            bail!(
                "[!] error: MsgKillAgent requires a signature, but the received packet contains None\n"
            );
        }
        Ok(())
    }

    /// Builds a `MsgFwdValues` containing the values fetched from other agents and sends it to
    /// the game's client.
    async fn send_msg_fwd_values(
        &self,
        peer_results: &Vec<PeerResult>,
        client_socket: &mut TcpStream,
    ) -> anyhow::Result<()> {
        let message = Message::build_msg_fwd_values(self.agent_id, peer_results)?;
        let message_signature = self.keys.sign(&message)?;

        let packet = Packet::build_packet(message, Some(message_signature))
            .context("[!] error: failed to build packet\n")?;

        match send_packet(&packet, client_socket).await {
            Ok(()) => Ok(()),
            Err(e) => bail!("[!] error: unable to forward values back to client - {}", e),
        }
    }

    /// Processes a `MsgFetchValues` received from the game's client. This method receives the
    /// addresses of peers as a Vec of `AgentConfig` instances and attempts to query each peer for
    /// its individual value with a `MsgQueryValue`. The received replies are then used to construct
    /// a `MsgFwdValues`. This method does not verify the signature of received replies, the task of
    /// performing authentication is delegated to the game's client upon receiving the `MsgFwdValues`.
    async fn handle_msg_fetch_values(
        &self,
        message_bytes: &[u8],
        signature: &Option<Vec<u8>>,
        client_socket: &mut TcpStream,
        agent_id: usize,
        peer_addresses: &Vec<AgentConfig>,
    ) -> anyhow::Result<()> {
        if let Some(signature) = signature {
            if agent_id == self.agent_id {
                Keys::verify(message_bytes, signature, &self.game_client_pubkey)?;
            } else {
                bail!("[!] error: Agent {} received MsgFetchValues, but message is addressed to Agent {}\n", 
                self.agent_id, agent_id);
            }
        } else {
            bail!(
                "[!] error: MsgFetchValues requires a signature, but the received packet contains None\n"
            );
        }

        let mut agent_conn_handles = Vec::new();
        let mut peer_results = Vec::new();
        let agent_arc = Arc::new(self.clone());

        for peer in peer_addresses {
            let address = peer.get_address();
            let port = peer.get_port();
            let peer_id = peer.get_id();
            let mut socket = match connect(address, port).await {
                Ok(socket) => socket,
                Err(e) => {
                    println!(
                        "[!] error: Agent {} failed to connect to (Agent ID: {} - {}:{}) - {}\n",
                        self.agent_id, peer_id, address, port, e
                    );
                    peer_results.push(PeerResult::Unreachable(peer_id));
                    continue;
                }
            };

            let querying_agent = agent_arc.clone();
            let handle =
                spawn(async move { Self::send_msg_query_value(querying_agent, &mut socket).await });
            agent_conn_handles.push((peer_id, handle));
        }

        for (peer_id, handle) in agent_conn_handles {
            match handle.await {
                Ok(Ok(peer_packet)) => {
                    peer_results.push(PeerResult::Reply(peer_packet));
                }
                Ok(Err(e)) => {
                    println!("{}", e);
                    peer_results.push(PeerResult::Unreachable(peer_id));
                }
                Err(e) => {
                    println!("[!] error: task panicked - {}\n", e);
                    peer_results.push(PeerResult::Unreachable(peer_id));
                }
            }
        }

        // If the agent is a liar, attempt to modify the results before forwarding them to the client
        if self.is_liar() {
            let received_results = peer_results.clone();
            if let Err(_) = self.tamper_with_messages(&mut peer_results) {
                // If tampering fails, revert back to the original results
                peer_results = received_results;
            }
        }

        self.send_msg_fwd_values(&peer_results, client_socket)
            .await?;

        Ok(())
    }

    /// Queries an individual agent peer for its value by sending a `MsgQueryValue`. This function
    /// does not perform the authentication of received messages.
    async fn send_msg_query_value(
        querying_agent: Arc<Self>,
        socket: &mut TcpStream,
    ) -> anyhow::Result<Packet> {
        let message = Message::build_msg_query_value()
            .context("[!] error: failed to build MsgQueryValue\n")?;

        let message_signature = querying_agent.keys.sign(&message)?;

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
            Ok(Message::MsgSendValue { .. }) => Ok(reply_packet),
            Ok(other) => bail!("[!] error: expected MsgSendValue, received {:?}\n", other),
            Err(e) => bail!("[!] error: unable to decode message - {}\n", e),
        }
    }

    /// Receives a packet and executes the required logic according to the type of message it contains.
    async fn packet_handler(
        &self,
        packet_bytes: &[u8],
        socket: &mut TcpStream,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<()> {
        let packet =
            Packet::unpack(packet_bytes).context("[!] error: unable to decode packet\n")?;
        let message = Message::deserialize_message(&packet.message);

        match message {
            Ok(Message::MsgQueryValue) => self.handle_msg_query_value(socket).await?,
            Ok(Message::MsgSendValue { .. }) => {
                bail!(
                    "[!] warning: Agent {} received an unexpected MsgSendValue",
                    self.agent_id
                );
            }
            Ok(Message::MsgKillAgent { agent_id }) => {
                if let Ok(()) =
                    self.handle_msg_kill_agent(&packet.message, &packet.msg_sig, agent_id)
                {
                    shutdown_token.cancel();
                }
            }
            Ok(Message::MsgFetchValues {
                agent_id,
                peer_addresses,
            }) => {
                self.handle_msg_fetch_values(
                    &packet.message,
                    &packet.msg_sig,
                    socket,
                    agent_id,
                    &peer_addresses,
                )
                .await?
            }
            Ok(Message::MsgFwdValues { .. }) => {
                bail!(
                    "[!] warning: Agent {} received an unexpected MsgSendValue",
                    self.agent_id
                );
            }
            Err(e) => println!("[!] error: unable to decode message - {}\n", e),
        }

        Ok(())
    }

    /// Processes incoming packets from an active TCP connection. This method reads packets from
    /// a `TcpStream` and handles them using internal packet handling logic.
    async fn connection_handler(
        &self,
        socket: &mut TcpStream,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<()> {
        let packet_bytes = recv_packet(socket).await?;
        self.packet_handler(&packet_bytes, socket, shutdown_token)
            .await?;
        Ok(())
    }

    /// Spawns a task to execute an instance of `Agent` and listen for incoming communication
    /// requests. The agent is bound to a network address specified by the fields `Agent.address`
    /// and `Agent.port`.
    pub async fn start_agent(&self, ready_signal: oneshot::Sender<usize>) {
        let listener = TcpListener::bind(format!("{}:{}", self.address, self.port)).await;
        let listener = match listener {
            Ok(listener) => listener,
            Err(e) => {
                println!(
                    "[!] error: failed to bind agent {} to address {}:{} - {}\n",
                    self.agent_id, self.address, self.port, e
                );
                return;
            }
        };

        println!(
            "{} (Agent ID: {} - Listening on: {}:{})\n",
            "[+] Spawned agent".bold(),
            self.agent_id,
            self.address,
            self.port
        );

        // Send a signal back to caller to inform that the agent has been spawned and
        // execution may continue
        let _ = ready_signal.send(self.agent_id);

        let cancellation_token = CancellationToken::new();

        loop {
            tokio::select! {
                conn = listener.accept() => {
                    if let Ok((mut socket, _)) = conn {
                        // NOTE: Cloning can be expensive, however, given that instances of `Agent`
                        // do not contain large amounts of data, using it here allows us to
                        // avoid the extra complexity of having to manage lifetimes.
                        let agent = self.clone();
                        let shutdown_token = cancellation_token.clone();

                        spawn(async move {
                            if let Err(e) = agent.connection_handler(&mut socket, shutdown_token)
                            .await {
                                println!("{}", e);
                            }
                        });
                    }
                }
                _ = cancellation_token.cancelled() => {
                    break;
                }
            }
        }
    }

    /// Returns a new unique port number for the `Agent.port` field.
    fn get_new_port() -> usize {
        BASE_PORT.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns a new unique ID for the `Agent.agent_id` field.
    fn get_new_id() -> usize {
        AGENT_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns an arbitrary `liar_value`, such that `liar_value` != `honest_value` and
    /// 1 <= `liar_value` <= `max_value`.
    fn get_liar_value(honest_value: u64, max_value: u64) -> u64 {
        let value_to_skip = honest_value;

        // Generate a value in [1, max_value] excluding value_to_skip, with uniform probability.
        // This avoids a "loop until different" approach, which could require a theoretically
        // unbounded number of retries (especially problematic when max_value is small).
        //
        // We use >= (not ==) because we need to shift ALL values at or above the skip point up by one.
        // Example with max_value=5, value_to_skip=3: range [1,4] maps to {1,2,4,5}
        //   - Values 1,2 stay unchanged (below skip point)
        //   - Values 3,4 become 4,5 (at or above skip point, shifted up)
        // Using == would cause collisions (both 3 and 4 would map to 4, and 5 would never appear).
        let mut liar_value = rand::thread_rng().gen_range(1..=(max_value - 1));
        if liar_value >= value_to_skip {
            liar_value += 1;
        }
        liar_value
    }
}

// ******************************************************************************************
// ************************************* UNIT TESTS *****************************************
// ******************************************************************************************

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liar_value_is_diff_from_honest() {
        // Must be careful when testing randomly generated values like this.
        // Even though the chance of the test failing is negligible for a
        // high number of iterations, for applications where security is critical
        // a more robust testing strategy should be used.
        let honest_value = 5;
        let max_value = 10;
        let iter = 10_000;

        for _ in 0..iter {
            let liar_value = Agent::get_liar_value(honest_value, max_value);
            assert_ne!(liar_value, 0, "Liar value cannot be 0");
            assert_ne!(
                liar_value, honest_value,
                "Liar value must be different from honest value"
            );
            assert!(
                liar_value <= max_value,
                "Liar value cannot be greater than max_value"
            );
        }
    }

    #[test]
    fn gen_unique_port() {
        let first_port = Agent::get_new_port();
        for i in 1..100 {
            let new_port = Agent::get_new_port();
            assert_eq!(first_port + i, new_port);
        }
    }

    #[test]
    fn gen_unique_agent_id() {
        let first_id = Agent::get_new_id();
        for i in 1..100 {
            let new_id = Agent::get_new_id();
            assert_eq!(first_id + i, new_id);
        }
    }

    #[test]
    fn test_agent_to_config() {
        let agent = Agent {
            agent_id: 1,
            value: 10,
            address: "127.0.0.1".to_owned(),
            port: 9001,
            keys: Keys::new_key_pair(),
            game_client_pubkey: "Hv9PImawhJ9+0ulJ/dlKjxTu+vKcKnyoJG5ahh4+DjY=".to_owned(),
            status: AgentStatus::Uninitialized,
            is_liar: false,
            tamper_chance: 0.0,
        };

        assert_eq!(
            agent.to_config(),
            AgentConfig::new(1, "127.0.0.1", 9001, agent.keys.get_public_key(),)
        );
    }

    #[test]
    fn test_tamper_with_messages_always_tampers_when_chance_is_100() {
        let agent = Agent {
            agent_id: 1,
            value: 10,
            address: "127.0.0.1".to_owned(),
            port: 9001,
            keys: Keys::new_key_pair(),
            game_client_pubkey: "Hv9PImawhJ9+0ulJ/dlKjxTu+vKcKnyoJG5ahh4+DjY=".to_owned(),
            status: AgentStatus::Uninitialized,
            is_liar: true,
            tamper_chance: 1.0,
        };

        let original_message = Message::build_msg_send_value(50, 2).unwrap();
        let packet = Packet::new(original_message.clone(), None);
        let mut peer_results = vec![PeerResult::Reply(packet)];

        agent.tamper_with_messages(&mut peer_results).unwrap();

        // A tamper_chance of 1.0 guarantees every entry is tampered with, either by corrupting
        // the forwarded message's bytes or by relabeling it as an unreachability claim.
        match &peer_results[0] {
            PeerResult::Reply(packet) => assert_ne!(packet.message, original_message),
            PeerResult::Unreachable(agent_id) => assert_eq!(*agent_id, 2),
        }
    }

    #[test]
    fn test_tamper_with_messages_never_tampers_when_chance_is_zero() {
        let agent = Agent {
            agent_id: 1,
            value: 10,
            address: "127.0.0.1".to_owned(),
            port: 9001,
            keys: Keys::new_key_pair(),
            game_client_pubkey: "Hv9PImawhJ9+0ulJ/dlKjxTu+vKcKnyoJG5ahh4+DjY=".to_owned(),
            status: AgentStatus::Uninitialized,
            is_liar: false,
            tamper_chance: 0.0,
        };

        let original_message = Message::build_msg_send_value(50, 2).unwrap();
        let packet = Packet::new(original_message.clone(), None);
        let mut peer_results = vec![PeerResult::Reply(packet)];

        agent.tamper_with_messages(&mut peer_results).unwrap();

        assert_eq!(
            peer_results[0],
            PeerResult::Reply(Packet::new(original_message, None))
        );
    }
}
