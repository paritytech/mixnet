// Copyright 2022 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Sphinx packet format.
//!
//! Packets consist of the following, in order:
//!
//! - [`Header`]:
//!   - Key-exchange public key ([`KxPublic`], alpha in the Sphinx paper).
//!   - [`Mac`] (gamma in the Sphinx paper).
//!   - Routing actions ([`Actions`], beta in the Sphinx paper).
//! - [`Payload`] (delta in the Sphinx paper):
//!   - [`PayloadData`].
//!   - [`PayloadTag`] (for detecting tampering).
//!
//! For each hop, the routing actions field contains, in order:
//!
//! - A [`RawAction`]. Always a deliver action for the last hop and a forward action for earlier
//!   hops.
//! - If the [`RawAction`] is [`RAW_ACTION_FORWARD_TO_PEER_ID`], a [`PeerId`].
//! - If the [`RawAction`] is a forward action, a [`Mac`] for the next hop.
//! - If the [`RawAction`] is [`RAW_ACTION_DELIVER_REPLY`], a [`SurbId`].
//! - If the [`RawAction`] is [`RAW_ACTION_DELIVER_COVER_WITH_ID`], a [`CoverId`].

/// Size in bytes of a [`KxPublic`].
pub const KX_PUBLIC_SIZE: usize = 32;
/// Key-exchange public key.
pub type KxPublic = [u8; KX_PUBLIC_SIZE];

pub const MAC_SIZE: usize = 16;
pub type Mac = [u8; MAC_SIZE];

/// Maximum number of hops a packet can traverse. Sending a packet directly to the final
/// destination node would count as one hop. Strictly speaking it is possible to construct packets
/// that will traverse slightly more hops than this, but not using this crate.
pub const MAX_HOPS: usize = 6;
pub const RAW_MIXNODE_INDEX_SIZE: usize = 2;
/// Raw mixnode index type, not guaranteed to be <= [`MAX_MIXNODE_INDEX`].
pub type RawMixnodeIndex = u16;
/// Maximum valid mixnode index.
pub const MAX_MIXNODE_INDEX: RawMixnodeIndex = 0xfeff;
pub const RAW_ACTION_SIZE: usize = RAW_MIXNODE_INDEX_SIZE; // A mixnode index means forward to that mixnode
pub type RawAction = RawMixnodeIndex;
pub const RAW_ACTION_FORWARD_TO_PEER_ID: RawAction = 0xff00;
pub const RAW_ACTION_DELIVER_REQUEST: RawAction = 0xff01;
pub const RAW_ACTION_DELIVER_REPLY: RawAction = 0xff02;
pub const RAW_ACTION_DELIVER_COVER: RawAction = 0xff03;
pub const RAW_ACTION_DELIVER_COVER_WITH_ID: RawAction = 0xff04;
/// Size in bytes of a [`PeerId`].
pub const PEER_ID_SIZE: usize = 32;
/// Globally unique identifier for a network peer. The [`core`](crate::core) module treats this as
/// an opaque type.
pub type PeerId = [u8; PEER_ID_SIZE];
/// Maximum amount of padding that might need to be appended to the routing actions for length
/// invariance at each hop.
pub const MAX_ACTIONS_PAD_SIZE: usize = RAW_ACTION_SIZE + PEER_ID_SIZE + MAC_SIZE;
pub const SURB_COVER_ID_SIZE: usize = 16;
pub const SURB_ID_SIZE: usize = SURB_COVER_ID_SIZE;
pub type SurbId = [u8; SURB_ID_SIZE];
pub const COVER_ID_SIZE: usize = SURB_COVER_ID_SIZE;
pub type CoverId = [u8; COVER_ID_SIZE];
pub const ACTIONS_SIZE: usize = (MAX_HOPS * (RAW_ACTION_SIZE + MAC_SIZE)) +
	PEER_ID_SIZE + // Allow one hop to use a peer ID
	SURB_COVER_ID_SIZE // Last hop may have a SURB ID or a cover ID...
	- MAC_SIZE; // ...but no next-hop MAC
pub type Actions = [u8; ACTIONS_SIZE];

pub const PAYLOAD_DATA_SIZE: usize = 2048;
pub type PayloadData = [u8; PAYLOAD_DATA_SIZE];
pub const PAYLOAD_TAG_SIZE: usize = 16;
pub type PayloadTag = [u8; PAYLOAD_TAG_SIZE];
pub const PAYLOAD_TAG: PayloadTag = [0; PAYLOAD_TAG_SIZE];

pub const HEADER_SIZE: usize = KX_PUBLIC_SIZE + MAC_SIZE + ACTIONS_SIZE;
pub type Header = [u8; HEADER_SIZE];
pub const PAYLOAD_SIZE: usize = PAYLOAD_DATA_SIZE + PAYLOAD_TAG_SIZE;
pub type Payload = [u8; PAYLOAD_SIZE];
/// Size in bytes of a [`Packet`].
pub const PACKET_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;
/// Type for packets sent between nodes. Note that all packets are the same size.
pub type Packet = [u8; PACKET_SIZE];
