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

// This module is largely based on the the Sphinx implementation by David Stainton
// at https://github.com/sphinx-cryptography/rust-sphinxcrypto
// and loosely follows Katzenpost specification.
//
// Notable changes include:
// * Switching to Lioness cipher for payload encryption.
// * Removing support for SURBs
// * Simplifying routing commands into a fixed structure.

///! Sphinx packet format.
mod crypto;

use crate::core::PACKET_SIZE;
use crypto::{PacketKeys, StreamCipher, GROUP_ELEMENT_SIZE, KEY_SIZE, MAC_SIZE, SPRP_KEY_SIZE};
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

pub type StaticSecret = x25519_dalek::StaticSecret;
pub type PublicKey = x25519_dalek::PublicKey;
pub type Delay = u32;
pub type NodeId = [u8; NODE_ID_SIZE];

/// Maximum hops the packet format supports.
pub const MAX_HOPS: usize = 5;
pub const OVERHEAD_SIZE: usize = HEADER_SIZE + PAYLOAD_TAG_SIZE;

/// The node identifier size in bytes.
const NODE_ID_SIZE: usize = 32;

/// Empty node id, last hop.
const TARGET_ID: NodeId = [0u8; NODE_ID_SIZE];

/// Empty node id, last hop, this is a surbs reply.
const TARGET_ID_WITH_SURBS: NodeId = [1u8; NODE_ID_SIZE];

/// The "authenticated data" portion of the Sphinx
/// packet header which as specified contains the
/// version number.
const AD_SIZE: usize = 2;

/// The first section of our Sphinx packet, the authenticated
/// unencrypted data containing version number.
const V0_AD: [u8; 2] = [0u8; 2];

/// The size in bytes of the payload tag.
const PAYLOAD_TAG_SIZE: usize = 16;

/// Standard payload without surbs.
const NO_SURBS: [u8; PAYLOAD_TAG_SIZE] = [0u8; PAYLOAD_TAG_SIZE];

/// Standard payload with surbs.
/// TODO consider putting this info in fragement header and keep 0 -> yes definitely TODO, then
/// revert the enum to option.
const WITH_SURBS: [u8; PAYLOAD_TAG_SIZE] = [1u8; PAYLOAD_TAG_SIZE];

/// The size of the Sphinx packet header in bytes.
pub(crate) const HEADER_SIZE: usize = AD_SIZE + GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;

/// Size of the surbs definition in payload.
pub(crate) const SURBS_REPLY_SIZE: usize = NODE_ID_SIZE + SPRP_KEY_SIZE + HEADER_SIZE;

/// The size in bytes of each routing info slot.
const PER_HOP_ROUTING_INFO_SIZE: usize = DELAY_SIZE + MAC_SIZE + NODE_ID_SIZE;

/// The size in bytes of the routing info section of the packet
/// header.
const ROUTING_INFO_SIZE: usize = PER_HOP_ROUTING_INFO_SIZE * MAX_HOPS;

const GROUP_ELEMENT_OFFSET: usize = AD_SIZE;
const ROUTING_INFO_OFFSET: usize = GROUP_ELEMENT_OFFSET + GROUP_ELEMENT_SIZE;
const MAC_OFFSET: usize = ROUTING_INFO_OFFSET + ROUTING_INFO_SIZE;

const DELAY_SIZE: usize = 4;
const NEXT_HOP_OFFSET: usize = DELAY_SIZE;
const NEXT_HOP_MAC_OFFSET: usize = NEXT_HOP_OFFSET + NODE_ID_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Invalid packet size or wrong authenticated data.
	InvalidPacket,
	/// Payload authentication mismatch.
	PayloadError,
	/// MAC mismatch.
	MACError,
	/// Payload decryption error.
	PayloadDecryptError,
	/// Payload encryption error.
	PayloadEncryptError,
	/// Surbs missing error.
	MissingSurbs,
}

/// PathHop describes a route hop that a Sphinx Packet will traverse,
#[derive(Clone)]
pub struct PathHop {
	/// Node id
	pub id: NodeId,
	/// ECDH Public key for the node.
	pub public_key: PublicKey,
	/// Optional delay measured in milliseconds. This should be random with exponential
	/// distribution.
	pub delay: Option<Delay>,
}

/// SprpKey is a struct that contains a SPRP (Strong Pseudo-Random Permutation) key.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct SprpKey {
	pub key: [u8; SPRP_KEY_SIZE],
}

impl SprpKey {
	// TODO rename, or remove by reusing the local key.
	pub fn new<T: Rng + CryptoRng>(rng: &mut T) -> Self {
		let mut raw_key: [u8; SPRP_KEY_SIZE] = [0u8; SPRP_KEY_SIZE];
		rng.fill_bytes(&mut raw_key);
		SprpKey { key: raw_key }
	}
}
fn blind(pk: PublicKey, factor: [u8; KEY_SIZE]) -> PublicKey {
	PublicKey::from(x25519_dalek::x25519(factor, pk.to_bytes()))
}

#[derive(Clone)]
struct NextHop {
	pub id: [u8; NODE_ID_SIZE],
	pub mac: [u8; MAC_SIZE],
}

pub enum Unwrapped {
	Forward((NodeId, Delay, Vec<u8>)),
	Payload(Vec<u8>),
	SurbsQuery(Vec<u8>, Vec<u8>),
	SurbsReply(Vec<u8>),
}

enum DoNextHop {
	Some(NextHop),
	Query,
	Reply,
}

pub struct SurbsPersistance {
	// TODO consider optional message.
	pub keys: Vec<SprpKey>,
}

impl SurbsPersistance {
	// use key to store surbs.
	fn surbs_id(&self) -> &SprpKey {
		self.keys.last().unwrap()
	}
}

// TODO rename SurbsEnvelop or SurbsReply?
#[derive(Eq, PartialEq, Debug)]
pub struct SurbsEncoded {
	pub id: [u8; NODE_ID_SIZE], // TODO rename first_node
	pub first_key: SprpKey,
	pub header: [u8; HEADER_SIZE],
}

impl From<Vec<u8>> for SurbsEncoded {
	fn from(mut encoded: Vec<u8>) -> Self {
		let buf = array_mut_ref![encoded, 0, SURBS_REPLY_SIZE];
		let (id, first_key, header) =
			mut_array_refs![buf, NODE_ID_SIZE, SPRP_KEY_SIZE, HEADER_SIZE];
		SurbsEncoded { id: *id, first_key: SprpKey { key: *first_key }, header: *header }
	}
}

impl SurbsEncoded {
	fn append(&self, dest: &mut Vec<u8>) {
		dest.extend_from_slice(&self.id[..]);
		dest.extend_from_slice(&self.first_key.key[..]);
		dest.extend_from_slice(&self.header[..]);
	}
}

struct EncodedHop<'a>(&'a mut [u8]);

impl<'a> EncodedHop<'a> {
	fn delay(&self) -> Delay {
		let mut bytes = [0u8; DELAY_SIZE];
		bytes.copy_from_slice(&self.0[0..DELAY_SIZE]);
		Delay::from_be_bytes(bytes)
	}

	fn next_hop(&self) -> DoNextHop {
		let mut id = [0u8; NODE_ID_SIZE];
		id.copy_from_slice(&self.0[NEXT_HOP_OFFSET..NEXT_HOP_OFFSET + NODE_ID_SIZE]);
		if id == TARGET_ID {
			DoNextHop::Query
		} else if id == TARGET_ID_WITH_SURBS {
			DoNextHop::Reply
		} else {
			let mut mac = [0u8; MAC_SIZE];
			mac.copy_from_slice(&self.0[NEXT_HOP_MAC_OFFSET..NEXT_HOP_MAC_OFFSET + MAC_SIZE]);
			DoNextHop::Some(NextHop { id, mac })
		}
	}

	fn set_delay(&mut self, delay: u32) {
		self.0[0..DELAY_SIZE].copy_from_slice(&delay.to_be_bytes());
	}

	fn set_next_hop(&mut self, hop: NextHop) {
		self.0[NEXT_HOP_OFFSET..NEXT_HOP_OFFSET + NODE_ID_SIZE].copy_from_slice(&hop.id);
		self.0[NEXT_HOP_MAC_OFFSET..NEXT_HOP_MAC_OFFSET + MAC_SIZE].copy_from_slice(&hop.mac);
	}
}

fn create_header<T: Rng + CryptoRng>(
	rng: &mut T,
	path: Vec<PathHop>,
	is_surbs: bool,
) -> Result<([u8; HEADER_SIZE], Vec<SprpKey>), Error> {
	let num_hops = path.len();
	// Derive the key material for each hop.
	let mut raw_key: [u8; KEY_SIZE] = Default::default();
	rng.fill_bytes(&mut raw_key);
	let secret_key = StaticSecret::from(raw_key);
	let mut group_elements: Vec<PublicKey> = vec![];
	let mut keys: Vec<PacketKeys> = vec![];
	let mut shared_secret: [u8; GROUP_ELEMENT_SIZE] =
		secret_key.diffie_hellman(&path[0].public_key).to_bytes();
	keys.push(crypto::kdf(&shared_secret));
	let mut group_element = PublicKey::from(&secret_key);
	group_elements.push(group_element.clone());

	let mut header = [0u8; HEADER_SIZE];
	header[0..AD_SIZE].copy_from_slice(&V0_AD);

	for i in 1..num_hops {
		// TODO for surbs last key do not need to be derived (it is only use by emmitter).
		shared_secret = secret_key.diffie_hellman(&path[i].public_key).to_bytes();
		let mut j = 0;
		while j < i {
			// TODO double loop is dumb,
			shared_secret = x25519_dalek::x25519(keys[j].blinding_factor, shared_secret);
			j += 1;
		}
		keys.push(crypto::kdf(&shared_secret));
		group_element = blind(group_element, keys[i - 1].blinding_factor);
		group_elements.push(group_element.clone());
	}

	// Derive the routing_information keystream and encrypted padding
	// for each hop.
	let mut ri_keystream: Vec<Vec<u8>> = vec![];
	let mut ri_padding: Vec<Vec<u8>> = vec![]; // TODO there is no need to have this buffer, can caluclate hmac in first loop
	for i in 0..num_hops {
		let mut steam_cipher =
			StreamCipher::new(&keys[i].header_encryption, &keys[i].header_encryption_iv);
		let stream = steam_cipher.generate(ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE); // Extra hop for padding
		let ks_len = stream.len() - ((i + 1) * PER_HOP_ROUTING_INFO_SIZE);
		ri_keystream.push(stream[..ks_len].to_vec());
		ri_padding.push(stream[ks_len..].to_vec());
		if i > 0 {
			let prev_pad_len = ri_padding[i - 1].len();
			let current = ri_padding[i - 1].clone();
			lioness::xor_assign(&mut ri_padding[i][..prev_pad_len], &current);
		}
	}

	// Create the routing_information block.
	let routing_info = &mut header[ROUTING_INFO_OFFSET..ROUTING_INFO_OFFSET + ROUTING_INFO_SIZE];
	let mut mac = [0u8; MAC_SIZE];

	let skipped_hops = MAX_HOPS - num_hops;
	if skipped_hops > 0 {
		rng.fill_bytes(&mut routing_info[(MAX_HOPS - skipped_hops) * PER_HOP_ROUTING_INFO_SIZE..]); // TODO isn't this padding?
	}
	if is_surbs {
		let offset = (num_hops - 1) * PER_HOP_ROUTING_INFO_SIZE + DELAY_SIZE;
		routing_info[offset..offset + NODE_ID_SIZE].copy_from_slice(&TARGET_ID_WITH_SURBS[..]);
	}
	let mut hop_index = num_hops - 1;
	loop {
		let hop_slice = &mut routing_info[hop_index * PER_HOP_ROUTING_INFO_SIZE..];
		let mut hop = EncodedHop(hop_slice);
		if hop_index != num_hops - 1 {
			hop.set_delay(path[hop_index + 1].delay.unwrap_or(0));
			hop.set_next_hop(NextHop { id: path[hop_index + 1].id, mac: mac.clone() });
		}

		lioness::xor_assign(hop_slice, ri_keystream[hop_index].as_slice());
		let padding = if hop_index > 0 { ri_padding[hop_index - 1].as_slice() } else { &[] };
		let mac_data = [&group_elements[hop_index].as_bytes()[..], hop_slice, padding];
		mac = crypto::hmac_list(&keys[hop_index].header_mac, &mac_data);

		if hop_index == 0 {
			break
		}
		hop_index -= 1;
	}

	// Assemble the completed Sphinx Packet Header and Sphinx Packet Payload
	// SPRP key vector.
	header[GROUP_ELEMENT_OFFSET..GROUP_ELEMENT_OFFSET + GROUP_ELEMENT_SIZE]
		.copy_from_slice(group_elements[0].as_bytes());
	header[MAC_OFFSET..].copy_from_slice(&mac);

	let mut sprp_keys = vec![];
	let mut i = 0;
	while i < num_hops {
		let k = SprpKey { key: keys[i].payload_encryption };
		sprp_keys.push(k);
		i += 1
	}
	return Ok((header, sprp_keys))
}

/// Create a new sphinx packet
pub fn new_packet<T: Rng + CryptoRng>(
	mut rng: T,
	path: Vec<PathHop>,
	payload: Vec<u8>,
	with_surbs: Option<(NodeId, Vec<PathHop>)>,
) -> Result<(Vec<u8>, Option<Vec<SprpKey>>), Error> {
	let (header, sprp_keys) = create_header(&mut rng, path, false)?;

	// prepend payload tag of zero bytes
	let mut tagged_payload;
	let surbs_key = if let Some((id, path)) = with_surbs {
		// TODO Box<[u8; FIX_LEN]>?? for all packet!!
		tagged_payload = Vec::with_capacity(PAYLOAD_TAG_SIZE + SURBS_REPLY_SIZE + payload.len());
		let (header, sprp_keys) = create_header(&mut rng, path, true)?;
		debug_assert!(header.len() == HEADER_SIZE);
		tagged_payload.resize(PAYLOAD_TAG_SIZE, 1u8);
		let first_key = SprpKey { key: sprp_keys[sprp_keys.len() - 1].key.clone() };
		let encoded = SurbsEncoded { id, first_key, header };
		debug_assert!(tagged_payload.len() == PAYLOAD_TAG_SIZE);
		encoded.append(&mut tagged_payload);
		debug_assert!(
			tagged_payload.len() == SURBS_REPLY_SIZE + PAYLOAD_TAG_SIZE,
			"{:?}",
			(tagged_payload.len(), SURBS_REPLY_SIZE + PAYLOAD_TAG_SIZE)
		);
		debug_assert!(
			crate::core::fragment::FRAGMENT_PACKET_SIZE == SURBS_REPLY_SIZE + payload.len()
		);
		Some(sprp_keys)
	} else {
		tagged_payload = Vec::with_capacity(PAYLOAD_TAG_SIZE + payload.len());
		tagged_payload.resize(PAYLOAD_TAG_SIZE, 0u8);
		None
	};
	tagged_payload.extend_from_slice(&payload);

	// encrypt tagged payload with SPRP
	for key in sprp_keys.into_iter().rev() {
		tagged_payload = crypto::sprp_encrypt(&key.key, tagged_payload)
			.map_err(|_| Error::PayloadEncryptError)?;
	}

	// attached Sphinx head to Sphinx body
	let mut packet: Vec<u8> = Vec::with_capacity(header.len() + tagged_payload.len());
	packet.extend_from_slice(&header);
	packet.extend_from_slice(&tagged_payload);
	return Ok((packet, surbs_key))
}

/// Create a new sphinx packet from a surbs header.
pub fn new_surbs_packet(
	first_key: SprpKey,
	message: Vec<u8>,
	surbs_header: [u8; HEADER_SIZE],
) -> Result<Vec<u8>, Error> {
	let mut tagged_payload = Vec::with_capacity(PAYLOAD_TAG_SIZE + message.len());
	tagged_payload.resize(PAYLOAD_TAG_SIZE, 0u8);
	tagged_payload.extend_from_slice(&message[..]);
	tagged_payload = crypto::sprp_encrypt(&first_key.key, tagged_payload)
		.map_err(|_| Error::PayloadEncryptError)?;

	let mut packet = Vec::with_capacity(PACKET_SIZE);
	packet.extend_from_slice(&surbs_header[..]);
	packet.extend_from_slice(&tagged_payload);
	debug_assert!(packet.len() == PACKET_SIZE);
	Ok(packet)
}

/// Unwrap one layer of encryption and return next layer information or the final payload.
pub fn unwrap_packet(
	private_key: &StaticSecret,
	mut packet: Vec<u8>,
	surbs: &mut SurbsCollection,
) -> Result<Unwrapped, Error> {
	// Split into mutable references and validate the AD
	if packet.len() < HEADER_SIZE {
		return Err(Error::InvalidPacket)
	}
	let (header, payload) = packet.split_at_mut(HEADER_SIZE);
	let (authed_header, header_mac) = header.split_at_mut(MAC_OFFSET);
	let (ad, _after_ad) = authed_header.split_at_mut(AD_SIZE);
	let after_ad = array_mut_ref![_after_ad, 0, GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE];
	let (group_element_bytes, routing_info) =
		mut_array_refs![after_ad, GROUP_ELEMENT_SIZE, ROUTING_INFO_SIZE];

	if ad.ct_eq(&V0_AD).unwrap_u8() == 0 {
		return Err(Error::InvalidPacket)
	}

	// Calculate the hop's shared secret, and replay_tag.
	let mut group_element = PublicKey::from(*group_element_bytes);
	let shared_secret = private_key.diffie_hellman(&group_element);

	// Derive the various keys required for packet processing.
	let keys = crypto::kdf(shared_secret.as_bytes());

	// Validate the Sphinx Packet Header.
	let mac_key = keys.header_mac;
	let mac_data = [&group_element_bytes[..], routing_info];
	let calculated_mac = crypto::hmac_list(&mac_key, &mac_data);

	// compare MAC in constant time
	if calculated_mac.ct_eq(header_mac).unwrap_u8() == 0 {
		return Err(Error::MACError)
	}

	// Append padding to preserve length invariance, decrypt the (padded)
	// routing_info block, and extract the section for the current hop.
	let mut stream_cipher = StreamCipher::new(&keys.header_encryption, &keys.header_encryption_iv);
	let mut a = [0u8; ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE];
	let mut b = [0u8; ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE];
	a[..ROUTING_INFO_SIZE].clone_from_slice(routing_info);
	stream_cipher.xor_key_stream(&mut b, &a);
	let (cmd_buf, new_routing_info) = b.split_at_mut(PER_HOP_ROUTING_INFO_SIZE);

	// Parse the per-hop routing commands.
	let hop = EncodedHop(cmd_buf);
	let maybe_next_hop = hop.next_hop();
	let delay = hop.delay(); // TODO remove delay and use our local mix strat?

	// Decrypt the Sphinx Packet Payload.
	let mut p = vec![0u8; payload.len()];
	p.copy_from_slice(&payload[..]);

	// Transform the packet for forwarding to the next mix
	match maybe_next_hop {
		DoNextHop::Some(next_hop) => {
			let decrypted_payload =
				crypto::sprp_decrypt(&keys.payload_encryption, payload.to_vec())
					.map_err(|_| Error::PayloadDecryptError)?;

			group_element = blind(group_element, keys.blinding_factor);
			group_element_bytes.copy_from_slice(group_element.as_bytes());
			routing_info.copy_from_slice(new_routing_info);
			header_mac.copy_from_slice(&next_hop.mac);
			payload.copy_from_slice(&decrypted_payload);
			Ok(Unwrapped::Forward((next_hop.id, delay, packet)))
		},
		DoNextHop::Query => {
			let mut decrypted_payload =
				crypto::sprp_decrypt(&keys.payload_encryption, payload.to_vec())
					.map_err(|_| Error::PayloadDecryptError)?;

			if decrypted_payload[..PAYLOAD_TAG_SIZE] == NO_SURBS {
				let _ = decrypted_payload.drain(..PAYLOAD_TAG_SIZE);
				Ok(Unwrapped::Payload(decrypted_payload))
			} else if decrypted_payload[..PAYLOAD_TAG_SIZE] == WITH_SURBS {
				let _ = decrypted_payload.drain(..PAYLOAD_TAG_SIZE);
				let payload = decrypted_payload.split_off(SURBS_REPLY_SIZE);
				Ok(Unwrapped::SurbsQuery(decrypted_payload, payload))
			} else {
				return Err(Error::PayloadError)
			}
		},
		DoNextHop::Reply => {
			let index = SprpKey { key: keys.payload_encryption };
			if let Some(surbs) = surbs.pending.remove(&index) {
				let mut decrypted_payload = payload.to_vec();
				let nb_key = surbs.keys.len();
				for key in surbs.keys[..nb_key - 1].iter().rev() {
					decrypted_payload = crypto::sprp_encrypt(&key.key, decrypted_payload)
						.map_err(|_| Error::PayloadDecryptError)?;
				}
				let first_key = &surbs.keys[nb_key - 1].key;
				decrypted_payload = crypto::sprp_decrypt(first_key, decrypted_payload)
					.map_err(|_| Error::PayloadDecryptError)?;
				if decrypted_payload[..PAYLOAD_TAG_SIZE] == NO_SURBS {
					let _ = decrypted_payload.drain(..PAYLOAD_TAG_SIZE);
				} else {
					return Err(Error::PayloadError)
				}
				Ok(Unwrapped::SurbsReply(decrypted_payload)) // TODO attach origin message??
			} else {
				log::trace!(target: "mixnet", "Surbs reply received after timeout {:?}", &index);
				return Err(Error::MissingSurbs)
			}
		},
	}
}

pub struct SurbsCollection {
	// TODO LRU this so we clean up old persistance.
	// TODO define collection in sphinx module? (rem lot of pub)
	pending: HashMap<SprpKey, SurbsPersistance>,
}

impl SurbsCollection {
	pub fn new() -> Self {
		SurbsCollection { pending: HashMap::new() }
	}

	pub fn insert(&mut self, surb: SurbsPersistance) {
		self.pending.insert(surb.surbs_id().clone(), surb);
	}
}
#[cfg(test)]
mod test {
	use super::{crypto::KEY_SIZE, NodeId, PathHop, PublicKey, StaticSecret, Unwrapped, MAX_HOPS};
	use rand::{rngs::OsRng, CryptoRng, RngCore};

	struct NodeParams {
		pub id: NodeId,
		pub private_key: StaticSecret,
	}

	fn new_node<T: RngCore + CryptoRng + Copy>(mut csprng: T) -> NodeParams {
		let mut id = NodeId::default();
		csprng.fill_bytes(&mut id);
		let mut raw_key: [u8; KEY_SIZE] = Default::default();
		csprng.fill_bytes(&mut raw_key);
		let private_key = StaticSecret::from(raw_key);
		NodeParams { id, private_key }
	}

	fn new_path_vector<T: RngCore + CryptoRng + Copy>(
		csprng: T,
		num_hops: u8,
	) -> (Vec<NodeParams>, Vec<PathHop>) {
		const DELAY_BASE: u32 = 123;

		// Generate the keypairs and node identifiers for the "nodes".
		let mut nodes = vec![];
		for _ in 0..num_hops {
			nodes.push(new_node(csprng));
		}

		// Assemble the path vector.
		let mut path = vec![];
		for i in 0..num_hops {
			let delay = DELAY_BASE * (i as u32 + 1);
			let public_key = PublicKey::from(&nodes[i as usize].private_key);
			path.push(PathHop { id: nodes[i as usize].id, public_key, delay: Some(delay) });
		}
		(nodes, path)
	}

	#[test]
	fn sphinx_forward_test() {
		let payload = b"We must defend our own privacy if we expect to have any. \
    We must come together and create systems which allow anonymous transactions to take place. \
    People have been defending their own privacy for centuries with whispers, darkness, envelopes, \
    closed doors, secret handshakes, and couriers. The technologies of the past did not allow for strong \
    privacy, but electronic technologies do.";

		// Generate the "nodes" and path for the forward sphinx packet.
		let mut num_hops = 1;
		while num_hops <= MAX_HOPS {
			let _tuple = new_path_vector(OsRng, num_hops as u8);
			let nodes = _tuple.0;
			let path = _tuple.1;
			let path_c = path.clone();
			let mut surbs_collection = super::SurbsCollection::new();

			// Create the packet.
			let (mut packet, surbs_keys) =
				super::new_packet(OsRng, path, payload.to_vec(), None).unwrap();
			if let Some(keys) = surbs_keys {
				let persistance = crate::core::sphinx::SurbsPersistance { keys };
				surbs_collection.insert(persistance);
			}

			// Unwrap the packet, validating the output.
			for i in 0..num_hops {
				let unwrap_result =
					super::unwrap_packet(&nodes[i].private_key, packet, &mut surbs_collection)
						.unwrap();

				if i == nodes.len() - 1 {
					let p = match unwrap_result {
						Unwrapped::Payload(p) => p,
						_ => panic!("Unexpected result"),
					};
					assert_eq!(p.as_slice(), &payload[..]);
					packet = Vec::new();
				} else {
					let (id, delay, next) = match unwrap_result {
						Unwrapped::Forward(f) => f,
						_ => panic!("Unexpected result"),
					};
					let hop = &path_c[i + 1];
					assert_eq!(delay, hop.delay.unwrap());
					assert_eq!(id, hop.id);
					packet = next;
				}
			}
			num_hops += 1;
		}
	}
}
