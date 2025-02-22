use xelis_common::{
    crypto::hash::Hash,
    serializer::{
        Writer,
        Serializer,
        ReaderError,
        Reader
    },
    utils::{
        ip_to_bytes,
        ip_from_bytes
    },
    block::Difficulty,
    api::daemon::{NotifyEvent, PeerPeerListUpdatedEvent, Direction}
};
use crate::{
    p2p::{peer::Peer, error::P2pError},
    config::P2P_PING_PEER_LIST_LIMIT,
    core::{blockchain::Blockchain, storage::Storage},
    rpc::rpc::get_peer_entry
};
use std::{
    fmt::Display,
    borrow::Cow,
    net::SocketAddr,
    sync::Arc
};
use log::{error, trace, debug};


#[derive(Clone, Debug)]
pub struct Ping<'a> {
    top_hash: Cow<'a, Hash>,
    topoheight: u64,
    height: u64,
    pruned_topoheight: Option<u64>,
    cumulative_difficulty: Difficulty,
    peer_list: Vec<SocketAddr>
}

impl<'a> Ping<'a> {
    pub fn new(top_hash: Cow<'a, Hash>, topoheight: u64, height: u64, pruned_topoheight: Option<u64>, cumulative_difficulty: Difficulty, peer_list: Vec<SocketAddr>) -> Self {
        Self {
            top_hash,
            topoheight,
            height,
            pruned_topoheight,
            cumulative_difficulty,
            peer_list
        }
    }

    pub async fn update_peer<S: Storage>(self, peer: &Arc<Peer>, blockchain: &Arc<Blockchain<S>>) -> Result<(), P2pError> {
        trace!("Updating {} with {}", peer, self);
        peer.set_block_top_hash(self.top_hash.into_owned()).await;
        peer.set_topoheight(self.topoheight);
        peer.set_height(self.height);

        if peer.is_pruned() && self.pruned_topoheight.is_none() {
            error!("Invalid protocol rules: impossible to change the pruned state (), from {} in ping packet", peer);
            return Err(P2pError::InvalidProtocolRules)
        }

        if let Some(pruned_topoheight) = self.pruned_topoheight {
            if pruned_topoheight > self.topoheight {
                error!("Invalid protocol rules: pruned topoheight {} is greater than height {} in ping packet", pruned_topoheight, self.height);
                return Err(P2pError::InvalidProtocolRules)
            }

            if let Some(old_pruned_topoheight) = peer.get_pruned_topoheight() {
                if pruned_topoheight < old_pruned_topoheight {
                    error!("Invalid protocol rules: pruned topoheight {} is less than old pruned topoheight {} in ping packet", pruned_topoheight, old_pruned_topoheight);
                    return Err(P2pError::InvalidProtocolRules)
                }
            }
        }

        peer.set_pruned_topoheight(self.pruned_topoheight);
        peer.set_cumulative_difficulty(self.cumulative_difficulty);

        trace!("Locking RPC Server to notify PeerStateUpdated event");
        if let Some(rpc) = blockchain.get_rpc().read().await.as_ref() {
            if rpc.is_event_tracked(&NotifyEvent::PeerStateUpdated).await {
                rpc.notify_clients_with(&NotifyEvent::PeerStateUpdated, get_peer_entry(peer).await).await;
            }
        }
        trace!("End locking for PeerStateUpdated event");

        if !self.peer_list.is_empty() {
            debug!("Received a peer list ({:?}) for {}", self.peer_list, peer.get_outgoing_address());
            let mut peers = peer.get_peers().lock().await;
            debug!("Our peer list is ({:?}) for {}", peers, peer.get_outgoing_address());
            let peer_addr = peer.get_connection().get_address();
            let peer_outgoing_addr = peer.get_outgoing_address();
            for addr in &self.peer_list {
                if peer_addr == addr || peer_outgoing_addr == addr {
                    error!("Invalid protocol rules: peer {} sent us its own socket address in ping packet", peer.get_outgoing_address());
                    return Err(P2pError::InvalidProtocolRules)
                }

                debug!("Adding {} for {} in ping packet", addr, peer.get_outgoing_address());
                if let Some(direction) = peers.get_mut(addr) {
                    if !direction.update_allow_in(Direction::In) {
                        error!("Invalid protocol rules: received duplicated peer {} from {} in ping packet", addr, peer.get_outgoing_address());
                        trace!("Received peer list: {:?}, our peerlist is: {:?}", self.peer_list, peers);
                        return Err(P2pError::InvalidProtocolRules)
                    }
                } else {
                    peers.insert(*addr, Direction::In);
                }
            }

            trace!("Locking RPC Server to notify PeerPeerListUpdated event");
            if let Some(rpc) = blockchain.get_rpc().read().await.as_ref() {
                if rpc.is_event_tracked(&NotifyEvent::PeerPeerListUpdated).await {
                    let value = PeerPeerListUpdatedEvent {
                        peer_id: peer.get_id(),
                        peerlist: self.peer_list
                    };
                    rpc.notify_clients_with(&NotifyEvent::PeerPeerListUpdated, value).await;
                }
            }
            trace!("End locking for PeerPeerListUpdated event");
        }

        Ok(())
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn get_peers(&self) -> &Vec<SocketAddr> {
        &self.peer_list
    }

    pub fn get_mut_peers(&mut self) -> &mut Vec<SocketAddr> {
        &mut self.peer_list
    }
}

impl Serializer for Ping<'_> {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.top_hash);
        writer.write_u64(&self.topoheight);
        writer.write_u64(&self.height);
        self.pruned_topoheight.write(writer);
        self.cumulative_difficulty.write(writer);
        writer.write_u8(self.peer_list.len() as u8);
        for peer in &self.peer_list {
            writer.write_bytes(&ip_to_bytes(peer));
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let top_hash = Cow::Owned(reader.read_hash()?);
        let topoheight = reader.read_u64()?;
        let height = reader.read_u64()?;
        let pruned_topoheight = Option::read(reader)?;
        if let Some(pruned_topoheight) = &pruned_topoheight {
            if *pruned_topoheight == 0 {
                debug!("Invalid pruned topoheight (0) in ping packet");
                return Err(ReaderError::InvalidValue)
            }
        }
        let cumulative_difficulty = Difficulty::read(reader)?;
        let peers_len = reader.read_u8()? as usize;
        if peers_len > P2P_PING_PEER_LIST_LIMIT {
            debug!("Too much peers sent in this ping packet: received {} while max is {}", peers_len, P2P_PING_PEER_LIST_LIMIT);
            return Err(ReaderError::InvalidValue)
        }

        let mut peer_list = Vec::with_capacity(peers_len);
        for _ in 0..peers_len {
            let peer = ip_from_bytes(reader)?;
            peer_list.push(peer);
        }

        Ok(Self { top_hash, topoheight, height, pruned_topoheight, cumulative_difficulty, peer_list })
    }
}

impl Display for Ping<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ping[top_hash: {}, topoheight: {}, height: {}, pruned topoheight: {:?}, peers length: {}]", self.top_hash, self.topoheight, self.height, self.pruned_topoheight, self.peer_list.len())
    }
}