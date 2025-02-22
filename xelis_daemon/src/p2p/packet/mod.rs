pub mod handshake;
pub mod chain;
pub mod ping;
pub mod object;
pub mod inventory;
pub mod bootstrap_chain;
pub mod peer_disconnected;

use self::bootstrap_chain::{BootstrapChainRequest, BootstrapChainResponse};
use self::inventory::{NotifyInventoryResponse, NotifyInventoryRequest};
use self::object::{ObjectRequest, ObjectResponse};
use self::chain::{ChainRequest, ChainResponse};
use self::handshake::Handshake;
use self::peer_disconnected::PacketPeerDisconnected;
use self::ping::Ping;
use std::borrow::Cow;
use log::{trace, error};
use xelis_common::{
    serializer::{Serializer, Reader, ReaderError, Writer},
    block::BlockHeader,
    crypto::hash::Hash
};

// All registered packet ids
const HANDSHAKE_ID: u8 = 0;
const TX_PROPAGATION_ID: u8 = 1;
const BLOCK_PROPAGATION_ID: u8 = 2;
const CHAIN_REQUEST_ID: u8 = 3;
const CHAIN_RESPONSE_ID: u8 = 4;
const PING_ID: u8 = 5;
const OBJECT_REQUEST_ID: u8 = 6;
const OBJECT_RESPONSE_ID: u8 = 7;
const NOTIFY_INV_REQUEST_ID: u8 = 8; 
const NOTIFY_INV_RESPONSE_ID: u8 = 9;
const BOOTSTRAP_CHAIN_REQUEST_ID: u8 = 10;
const BOOTSTRAP_CHAIN_RESPONSE_ID: u8 = 11;
const PEER_DISCONNECTED_ID: u8 = 12;

// PacketWrapper allows us to link any Packet to a Ping
#[derive(Debug)]
pub struct PacketWrapper<'a, T: Serializer + Clone> {
    packet: Cow<'a, T>,
    ping: Cow<'a, Ping<'a>>
}

impl<'a, T: Serializer + Clone> PacketWrapper<'a, T> {
    pub fn new(packet: Cow<'a, T>, ping: Cow<'a, Ping<'a>>) -> Self {
        Self {
            packet,
            ping
        }
    }

    pub fn consume(self) -> (Cow<'a, T>, Cow<'a, Ping<'a>>) {
        (self.packet, self.ping)
    }
}

impl<'a, T: Serializer + Clone> Serializer for PacketWrapper<'a, T> {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let packet = T::read(reader)?;
        let packet = Cow::Owned(packet);
        let ping = Cow::Owned(Ping::read(reader)?);

        Ok(Self::new(packet, ping))
    }

    fn write(&self, writer: &mut Writer) {
        self.packet.write(writer);   
        self.ping.write(writer);
    }
}

#[derive(Debug)]
pub enum Packet<'a> {
    Handshake(Cow<'a, Handshake>), // first packet to connect to a node
    // packet contains tx hash, view this packet as a "notification"
    // instead of sending the TX directly, we notify our peers
    // so the peer that already have this TX in mempool don't have to read it again
    // imo: can be useful when the network is spammed by alot of txs
    TransactionPropagation(PacketWrapper<'a, Hash>),
    BlockPropagation(PacketWrapper<'a, BlockHeader>),
    ChainRequest(PacketWrapper<'a, ChainRequest>),
    ChainResponse(ChainResponse),
    Ping(Cow<'a, Ping<'a>>),
    ObjectRequest(Cow<'a, ObjectRequest>),
    ObjectResponse(ObjectResponse<'a>),
    NotifyInventoryRequest(PacketWrapper<'a, NotifyInventoryRequest>),
    NotifyInventoryResponse(NotifyInventoryResponse<'a>),
    BootstrapChainRequest(BootstrapChainRequest<'a>),
    BootstrapChainResponse(BootstrapChainResponse),
    PeerDisconnected(PacketPeerDisconnected)
}

impl<'a> Serializer for Packet<'a> {
    fn read(reader: &mut Reader) -> Result<Packet<'a>, ReaderError> {
        let id = reader.read_u8()?;
        trace!("Packet ID received: {}, size: {}", id, reader.total_size());
        Ok(match id {
            HANDSHAKE_ID => Packet::Handshake(Cow::Owned(Handshake::read(reader)?)),
            TX_PROPAGATION_ID => Packet::TransactionPropagation(PacketWrapper::read(reader)?),
            BLOCK_PROPAGATION_ID => Packet::BlockPropagation(PacketWrapper::read(reader)?),
            CHAIN_REQUEST_ID => Packet::ChainRequest(PacketWrapper::read(reader)?),
            CHAIN_RESPONSE_ID => Packet::ChainResponse(ChainResponse::read(reader)?),
            PING_ID => Packet::Ping(Cow::Owned(Ping::read(reader)?)),
            OBJECT_REQUEST_ID => Packet::ObjectRequest(Cow::Owned(ObjectRequest::read(reader)?)),
            OBJECT_RESPONSE_ID => Packet::ObjectResponse(ObjectResponse::read(reader)?),
            NOTIFY_INV_REQUEST_ID => Packet::NotifyInventoryRequest(PacketWrapper::read(reader)?), 
            NOTIFY_INV_RESPONSE_ID => Packet::NotifyInventoryResponse(NotifyInventoryResponse::read(reader)?),
            BOOTSTRAP_CHAIN_REQUEST_ID => Packet::BootstrapChainRequest(BootstrapChainRequest::read(reader)?),
            BOOTSTRAP_CHAIN_RESPONSE_ID => Packet::BootstrapChainResponse(BootstrapChainResponse::read(reader)?),
            PEER_DISCONNECTED_ID => Packet::PeerDisconnected(PacketPeerDisconnected::read(reader)?),
            id => {
                error!("invalid packet id received: {}", id);
                return Err(ReaderError::InvalidValue)
            }
        })
    }

    fn write(&self, writer: &mut Writer) {
        let (id, serializer): (u8, &dyn Serializer) = match self {
            Packet::Handshake(handshake) => (HANDSHAKE_ID, handshake.as_ref()),
            Packet::TransactionPropagation(tx) => (TX_PROPAGATION_ID, tx),
            Packet::BlockPropagation(block) => (BLOCK_PROPAGATION_ID, block),
            Packet::ChainRequest(request) => (CHAIN_REQUEST_ID, request),
            Packet::ChainResponse(response) => (CHAIN_RESPONSE_ID, response),
            Packet::Ping(ping) => (PING_ID, ping.as_ref()),
            Packet::ObjectRequest(request) => (OBJECT_REQUEST_ID, request.as_ref()),
            Packet::ObjectResponse(response) => (OBJECT_RESPONSE_ID, response),
            Packet::NotifyInventoryRequest(request) => (NOTIFY_INV_REQUEST_ID, request),
            Packet::NotifyInventoryResponse(inventory) => (NOTIFY_INV_RESPONSE_ID, inventory),
            Packet::BootstrapChainRequest(request) => (BOOTSTRAP_CHAIN_REQUEST_ID, request),
            Packet::BootstrapChainResponse(response) => (BOOTSTRAP_CHAIN_RESPONSE_ID, response),
            Packet::PeerDisconnected(disconnected) => (PEER_DISCONNECTED_ID, disconnected)
        };

        let packet = serializer.to_bytes();
        let packet_len: u32 = packet.len() as u32 + 1;
        writer.write_u32(&packet_len);
        writer.write_u8(id);
        writer.write_bytes(&packet);
    }
}