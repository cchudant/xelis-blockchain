use crate::core::error::BlockchainError;
use tokio::sync::AcquireError;
use tokio::sync::mpsc::error::SendError as TSendError;
use tokio::sync::oneshot::error::RecvError;
use xelis_common::crypto::hash::Hash;
use xelis_common::serializer::ReaderError;
use std::array::TryFromSliceError;
use std::net::{AddrParseError, SocketAddr};
use tokio::time::error::Elapsed;
use std::sync::mpsc::SendError;
use std::io::Error as IOError;
use std::sync::PoisonError;
use thiserror::Error;

use super::packet::bootstrap_chain::StepKind;
use super::packet::object::ObjectRequest;

#[derive(Error, Debug)]
pub enum P2pError {
    #[error("Incompatible direction received")]
    InvalidDirection,
    #[error("Invalid protocol rules")]
    InvalidProtocolRules,
    #[error("Invalid list size in pagination with a next page")]
    InvalidInventoryPagination,
    #[error("unknown common peer {} received: not found in list", _0)]
    UnknownPeerReceived(SocketAddr),
    #[error("Block {} at height {} propagated is under our stable height", _0, _1)]
    BlockPropagatedUnderStableHeight(Hash, u64),
    #[error("Block {} propagated is already tracked", _0)]
    AlreadyTrackedBlock(Hash),
    #[error("Transaction {} propagated is already tracked", _0)]
    AlreadyTrackedTx(Hash),
    #[error("Malformed chain request, received {} blocks id", _0)]
    MalformedChainRequest(usize),
    #[error("Received a unrequested chain response")]
    UnrequestedChainResponse,
    #[error("Invalid chain response size, got {} blocks while maximum set was {}", _0, _1)]
    InvaliChainResponseSize(usize, usize),
    #[error("Received a unrequested bootstrap chain response")]
    UnrequestedBootstrapChainResponse,
    #[error("Invalid common point at topoheight {}", _0)]
    InvalidCommonPoint(u64),
    #[error("Peer disconnected")]
    Disconnected,
    #[error("Invalid handshake")]
    InvalidHandshake,
    #[error("Expected Handshake packet")]
    ExpectedHandshake,
    #[error("Invalid peer address, {}", _0)]
    InvalidPeerAddress(String), // peer address from handshake
    #[error("Invalid network")]
    InvalidNetwork,
    #[error("Invalid network ID")]
    InvalidNetworkID,
    #[error("Peer id {} is already used!", _0)]
    PeerIdAlreadyUsed(u64),
    #[error("Peer already connected: {}", _0)]
    PeerAlreadyConnected(String),
    #[error(transparent)]
    ErrorStd(#[from] IOError),
    #[error("Poison Error: {}", _0)]
    PoisonError(String),
    #[error("Send Error: {}", _0)]
    SendError(String),
    #[error(transparent)]
    TryInto(#[from] TryFromSliceError),
    #[error(transparent)]
    ReaderError(#[from] ReaderError),
    #[error(transparent)]
    ParseAddressError(#[from] AddrParseError),
    #[error("Invalid packet ID")]
    InvalidPacket,
    #[error("Peer topoheight is higher than our")]
    InvalidRequestedTopoheight,
    #[error("Packet size exceed limit")]
    InvalidPacketSize,
    #[error("Received valid packet with not used bytes")]
    InvalidPacketNotFullRead,
    #[error("Request sync chain too fast")]
    RequestSyncChainTooFast,
    #[error(transparent)]
    AsyncTimeOut(#[from] Elapsed),
    #[error("No response received from peer")]
    NoResponse,
    #[error("Invalid object hash, expected: {}, got: {}", _0, _1)]
    InvalidObjectHash(Hash, Hash),
    #[error("Object requested {} not found", _0)]
    ObjectNotFound(ObjectRequest),
    #[error("Object not requested {}", _0)]
    ObjectNotRequested(ObjectRequest),
    #[error("Object requested {} is not present any more in queue", _0)]
    ObjectHashNotPresentInQueue(Hash),
    #[error("Object requested {} already requested", _0)]
    ObjectAlreadyRequested(ObjectRequest),
    #[error("Invalid object response for request, received hash: {}", _0)]
    InvalidObjectResponse(Hash),
    #[error("Invalid object response type for request")]
    InvalidObjectResponseType,
    #[error(transparent)]
    ObjectRequestError(#[from] RecvError),
    #[error("Expected a block type")]
    ExpectedBlock,
    #[error("Expected a transaction type")]
    ExpectedTransaction,
    #[error("Peer sent us a peerlist faster than protocol rules")]
    PeerInvalidPeerListCountdown,
    #[error("Peer sent us a ping packet faster than protocol rules")]
    PeerInvalidPingCoutdown,
    #[error(transparent)]
    BlockchainError(#[from] Box<BlockchainError>),
    #[error("Invalid content in peerlist file")]
    InvalidPeerlist,
    #[error("Invalid bootstrap chain step, expected {:?}, got {:?}", _0, _1)]
    InvalidBootstrapStep(StepKind, StepKind),
    #[error("Error while serde JSON: {}", _0)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    SemaphoreAcquireError(#[from] AcquireError)
}

impl From<BlockchainError> for P2pError {
    fn from(err: BlockchainError) -> Self {
        Self::BlockchainError(Box::new(err))
    }
}


impl<T> From<PoisonError<T>> for P2pError {
    fn from(err: PoisonError<T>) -> Self {
        Self::PoisonError(format!("{}", err))
    }
}

impl<T> From<SendError<T>> for P2pError {
    fn from(err: SendError<T>) -> Self {
        Self::SendError(format!("{}", err))
    }
}

impl<T> From<TSendError<T>> for P2pError {
    fn from(err: TSendError<T>) -> Self {
        Self::SendError(format!("{}", err))
    }
}