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
//! - `Header`:
//!   - Key-exchange public key (`KxPublic`, alpha in the Sphinx paper).
//!   - `Mac` (gamma in the Sphinx paper).
//!   - `EncryptedHeader` (beta in the Sphinx paper).
//! - `Payload` (delta in the Sphinx paper):
//!   - `PayloadData`.
//!   - `PayloadTag` (for detecting tampering).
//!
//! For each hop, the encrypted header contains, in order:
//!
//! - A `RawAction`. Always a deliver action for the last hop and a forward action for earlier hops.
//! - If the `RawAction` is `RAW_ACTION_FORWARD_TO_PEER_ID`, a `PeerId`.
//! - If the `RawAction` is a forward action, a `Mac` for the next hop.
//! - If the `RawAction` is `RAW_ACTION_DELIVER_REPLY`, a `SurbId`.
//! - If the `RawAction` is `RAW_ACTION_DELIVER_COVER_WITH_ID`, a `CoverId`.

pub const KX_PUBLIC_SIZE: usize = 32;
pub type KxPublic = [u8; KX_PUBLIC_SIZE];

pub const MAC_SIZE: usize = 16;
pub type Mac = [u8; MAC_SIZE];

pub const MAX_HOPS: usize = 6;
pub const RAW_MIXNODE_INDEX_SIZE: usize = 2;
pub type RawMixnodeIndex = u16;
pub const MAX_MIXNODE_INDEX: RawMixnodeIndex = 0xfeff;
pub const RAW_ACTION_SIZE: usize = RAW_MIXNODE_INDEX_SIZE; // A mixnode index means forward to that mixnode
pub type RawAction = RawMixnodeIndex;
pub const RAW_ACTION_FORWARD_TO_PEER_ID: RawAction = 0xff00;
pub const RAW_ACTION_DELIVER_REQUEST: RawAction = 0xff01;
pub const RAW_ACTION_DELIVER_REPLY: RawAction = 0xff02;
pub const RAW_ACTION_DELIVER_COVER: RawAction = 0xff03;
pub const RAW_ACTION_DELIVER_COVER_WITH_ID: RawAction = 0xff04;
pub const PEER_ID_SIZE: usize = 32;
pub type PeerId = [u8; PEER_ID_SIZE];
/// Maximum amount of padding that might need to be appended to the header for length invariance at
/// each hop.
pub const MAX_HEADER_PAD_SIZE: usize = RAW_ACTION_SIZE + PEER_ID_SIZE + MAC_SIZE;
pub const SURB_COVER_ID_SIZE: usize = 16;
pub const SURB_ID_SIZE: usize = SURB_COVER_ID_SIZE;
pub type SurbId = [u8; SURB_ID_SIZE];
pub const COVER_ID_SIZE: usize = SURB_COVER_ID_SIZE;
pub type CoverId = [u8; COVER_ID_SIZE];
pub const ENCRYPTED_HEADER_SIZE: usize = (MAX_HOPS * (RAW_ACTION_SIZE + MAC_SIZE)) +
	PEER_ID_SIZE + // Allow one hop to use a peer ID
	SURB_COVER_ID_SIZE // Last hop may have a SURB ID or a cover ID...
	- MAC_SIZE; // ...but no next-hop MAC
pub type EncryptedHeader = [u8; ENCRYPTED_HEADER_SIZE];

pub const PAYLOAD_DATA_SIZE: usize = 2048;
pub type PayloadData = [u8; PAYLOAD_DATA_SIZE];
pub const PAYLOAD_TAG_SIZE: usize = 16;
pub type PayloadTag = [u8; PAYLOAD_TAG_SIZE];
pub const PAYLOAD_TAG: PayloadTag = [0; PAYLOAD_TAG_SIZE];

pub const HEADER_SIZE: usize = KX_PUBLIC_SIZE + MAC_SIZE + ENCRYPTED_HEADER_SIZE;
pub type Header = [u8; HEADER_SIZE];
pub const PAYLOAD_SIZE: usize = PAYLOAD_DATA_SIZE + PAYLOAD_TAG_SIZE;
pub type Payload = [u8; PAYLOAD_SIZE];
pub const PACKET_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;
pub type Packet = [u8; PACKET_SIZE];
