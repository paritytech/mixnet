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

//! Sphinx packet building.

use super::{
	crypto::*,
	delay::Delay,
	packet::*,
	target::{MixnodeIndex, Target},
};
use arrayref::{array_mut_ref, array_refs, mut_array_refs};
use arrayvec::ArrayVec;
use rand::{CryptoRng, Rng};

fn mut_arr_at<T, const N: usize>(slice: &mut [T], offset: usize) -> &mut [T; N] {
	(&mut slice[offset..offset + N])
		.try_into()
		.expect("Slice length is fixed and matches array length")
}

enum PacketKind<'a> {
	Request,
	Reply(&'a SurbId),
	Cover(Option<&'a CoverId>),
}

/// Build a Sphinx header. `targets` should not include the first hop. At most one target may be a
/// peer ID; all others should be mixnode indices. Returns the total forwarding delay across all
/// hops.
fn build_header(
	header: &mut Header,
	kx_shared_secrets: &mut ArrayVec<KxSharedSecret, MAX_HOPS>,
	rng: &mut (impl Rng + CryptoRng),
	targets: &[Target],
	their_kx_publics: &[KxPublic],
	kind: PacketKind,
) -> Delay {
	debug_assert_eq!(targets.len() + 1, their_kx_publics.len());
	debug_assert!(their_kx_publics.len() <= MAX_HOPS);

	let (kx_public, mac_plus_encrypted) =
		mut_array_refs![header, KX_PUBLIC_SIZE, MAC_SIZE + ENCRYPTED_HEADER_SIZE];

	gen_kx_public_and_shared_secrets(kx_public, kx_shared_secrets, rng, their_kx_publics);

	// Encrypted part of the header, and current write offset into
	let encrypted = array_mut_ref![mac_plus_encrypted, MAC_SIZE, ENCRYPTED_HEADER_SIZE];
	let mut offset = 0;

	// Total forwarding delay across all hops
	let mut total_delay = Delay::zero();

	// We loop over the hops forward and then backward. Data that is generated by the first pass
	// for the second pass is stashed here. The last hop is handled specially so is excluded here.
	struct Hop {
		mac_key: MacKey,
		encryption_keystream: [u8; ENCRYPTED_HEADER_SIZE + MAX_HEADER_PAD_SIZE],
		start_offset: u16, // Starting offset of hop in encrypted
	}
	let mut hops: ArrayVec<Hop, { MAX_HOPS - 1 }> = ArrayVec::new();

	// Header padding for length invariance, generated from the header encryption keystreams. This
	// is only needed for computing the MACs.
	let mut pad = [0; ENCRYPTED_HEADER_SIZE - RAW_ACTION_SIZE];

	// Loop over hops forward (excluding the last hop)
	for (target, kx_shared_secret) in targets.iter().zip(kx_shared_secrets.iter()) {
		// Write target into the header
		let start_offset = offset;
		offset += RAW_ACTION_SIZE;
		let raw_action = match target {
			Target::MixnodeIndex(mixnode_index) => mixnode_index.get(),
			Target::PeerId(peer_id) => {
				*mut_arr_at(encrypted, offset) = *peer_id;
				offset += PEER_ID_SIZE;
				RAW_ACTION_FORWARD_TO_PEER_ID
			},
		};
		*mut_arr_at(encrypted, start_offset) = raw_action.to_le_bytes();

		// The MAC for the next hop can't be computed yet. Leave a gap for it. Note that this is
		// always the last thing in the header for the hop; this is assumed by the backward loop.
		offset += MAC_SIZE;

		let sds = SmallDerivedSecrets::new(kx_shared_secret);

		total_delay += Delay::from_seed(sds.delay_seed());

		hops.push(Hop {
			mac_key: *sds.mac_key(),
			encryption_keystream: [0; ENCRYPTED_HEADER_SIZE + MAX_HEADER_PAD_SIZE],
			start_offset: start_offset as u16,
		});
		let encryption_keystream =
			&mut hops.last_mut().expect("Just pushed, so not empty").encryption_keystream;
		apply_header_encryption_keystream(encryption_keystream, sds.header_encryption_key());

		// At the end of the loop, pad will contain the padding as seen by the last hop (before
		// decryption)
		apply_keystream(
			&mut pad[..offset],
			&encryption_keystream[ENCRYPTED_HEADER_SIZE - start_offset..],
		);
	}

	// Handle the last hop
	{
		// Write deliver action into the header
		let start_offset = offset;
		offset += RAW_ACTION_SIZE;
		let raw_action = match kind {
			PacketKind::Request => RAW_ACTION_DELIVER_REQUEST,
			PacketKind::Reply(surb_id) => {
				*mut_arr_at(encrypted, offset) = *surb_id;
				offset += SURB_ID_SIZE;
				RAW_ACTION_DELIVER_REPLY
			},
			PacketKind::Cover(None) => RAW_ACTION_DELIVER_COVER,
			PacketKind::Cover(Some(cover_id)) => {
				*mut_arr_at(encrypted, offset) = *cover_id;
				offset += COVER_ID_SIZE;
				RAW_ACTION_DELIVER_COVER_WITH_ID
			},
		};
		*mut_arr_at(encrypted, start_offset) = raw_action.to_le_bytes();

		// Fill the remainder of the header with random bytes, so the last hop cannot determine the
		// path length
		rng.fill_bytes(&mut encrypted[offset..]);

		let sds =
			SmallDerivedSecrets::new(kx_shared_secrets.last().expect("There is at least one hop"));

		// Encrypt the header for the last hop. Note that the padding is not touched here; it is
		// generated entirely from the keystreams for earlier hops, and effectively gets scrambled
		// even further when the last hop "decrypts" it.
		apply_header_encryption_keystream(
			&mut encrypted[start_offset..],
			sds.header_encryption_key(),
		);

		// Compute the MAC for the last hop and place it in the appropriate place in the header
		// (right before the last hop action)
		*mut_arr_at(mac_plus_encrypted, start_offset) =
			compute_mac(&encrypted[start_offset..], &pad[..start_offset], sds.mac_key());
	}

	// Loop over hops backward (excluding the last hop, which has already been handled)
	for hop in hops.iter().rev() {
		let start_offset = hop.start_offset as usize;

		// Encrypt the header and padding for the hop
		apply_keystream(
			&mut mac_plus_encrypted[MAC_SIZE + start_offset..],
			&hop.encryption_keystream,
		);
		apply_keystream(
			&mut pad[..start_offset],
			&hop.encryption_keystream[ENCRYPTED_HEADER_SIZE - start_offset..],
		);

		// Compute the MAC for the hop and place it in the appropriate place in the header (right
		// before the hop action)
		*mut_arr_at(mac_plus_encrypted, start_offset) = compute_mac(
			&mac_plus_encrypted[MAC_SIZE + start_offset..],
			&pad[..start_offset],
			&hop.mac_key,
		);
	}

	total_delay
}

/// Returns a mutable reference to the payload data in `packet`. This is only really useful for
/// filling in the payload data prior to calling [`complete_request_packet`] or
/// [`complete_reply_packet`].
pub fn mut_payload_data(packet: &mut Packet) -> &mut PayloadData {
	array_mut_ref![packet, HEADER_SIZE, PAYLOAD_DATA_SIZE]
}

/// Complete a Sphinx request packet. The unencrypted payload data should be written to
/// [`mut_payload_data(packet)`](mut_payload_data) before calling this function. `targets` should
/// not include the first hop. At most one target may be a peer ID; all others should be mixnode
/// indices. Returns the total forwarding delay across all hops.
pub fn complete_request_packet(
	packet: &mut Packet,
	rng: &mut (impl Rng + CryptoRng),
	targets: &[Target],
	their_kx_publics: &[KxPublic],
) -> Delay {
	debug_assert_eq!(targets.len() + 1, their_kx_publics.len());
	debug_assert!(their_kx_publics.len() <= MAX_HOPS);

	let (header, payload) = mut_array_refs![packet, HEADER_SIZE, PAYLOAD_SIZE];

	// Build the header
	let mut kx_shared_secrets = ArrayVec::new();
	let total_delay = build_header(
		header,
		&mut kx_shared_secrets,
		rng,
		targets,
		their_kx_publics,
		PacketKind::Request,
	);

	// Force the payload tag
	*array_mut_ref![payload, PAYLOAD_DATA_SIZE, PAYLOAD_TAG_SIZE] = PAYLOAD_TAG;

	// Encrypt the payload
	for kx_shared_secret in kx_shared_secrets.iter().rev() {
		encrypt_payload(payload, &derive_payload_encryption_key(kx_shared_secret));
	}

	total_delay
}

/// Size in bytes of a [`Surb`].
pub const SURB_SIZE: usize = RAW_MIXNODE_INDEX_SIZE + HEADER_SIZE + PAYLOAD_ENCRYPTION_KEY_SIZE;
/// A "single-use reply block". This should be treated as an opaque type.
pub type Surb = [u8; SURB_SIZE];

pub type SurbPayloadEncryptionKeys = ArrayVec<PayloadEncryptionKey, MAX_HOPS>;

/// Build a SURB. Note that unlike in the Sphinx paper, the last hop (which should be this node)
/// decrypts the payload, rather than adding another layer of encryption and forwarding to the
/// "destination". So the number of payload encryption keys matches the number of hops. The first
/// hop must have a mixnode index, specified by `first_mixnode_index`. `targets` specifies the
/// remaining hops. At most one target may be a peer ID; all others should be mixnode indices.
/// Returns the total forwarding delay across all hops.
pub fn build_surb(
	surb: &mut Surb,
	payload_encryption_keys: &mut SurbPayloadEncryptionKeys,
	rng: &mut (impl Rng + CryptoRng),
	first_mixnode_index: MixnodeIndex,
	targets: &[Target],
	their_kx_publics: &[KxPublic],
	id: &SurbId,
) -> Delay {
	debug_assert_eq!(targets.len() + 1, their_kx_publics.len());
	debug_assert!(their_kx_publics.len() <= MAX_HOPS);

	let (raw_first_mixnode_index, header, first_payload_encryption_key) =
		mut_array_refs![surb, RAW_MIXNODE_INDEX_SIZE, HEADER_SIZE, PAYLOAD_ENCRYPTION_KEY_SIZE];

	*raw_first_mixnode_index = first_mixnode_index.get().to_le_bytes();

	// Build the header
	let mut kx_shared_secrets = ArrayVec::new();
	let total_delay = build_header(
		header,
		&mut kx_shared_secrets,
		rng,
		targets,
		their_kx_publics,
		PacketKind::Reply(id),
	);

	// Generate the payload encryption keys. The first key is totally random, the rest are derived
	// from the key-exchange shared secrets.
	rng.fill_bytes(first_payload_encryption_key);
	payload_encryption_keys.push(*first_payload_encryption_key);
	kx_shared_secrets.pop(); // Last hop does not encrypt
	for kx_shared_secret in &kx_shared_secrets {
		payload_encryption_keys.push(derive_payload_encryption_key(kx_shared_secret));
	}

	total_delay
}

/// Complete a Sphinx reply packet. The unencrypted payload data should be written to
/// [`mut_payload_data(packet)`](mut_payload_data) before calling this function. `surb` should be a
/// SURB built by the receiving node using [`build_surb`]. The mixnode index of the first hop is
/// returned. Will only return [`None`] if the SURB is malformed.
pub fn complete_reply_packet(packet: &mut Packet, surb: &Surb) -> Option<MixnodeIndex> {
	let (header, payload) = mut_array_refs![packet, HEADER_SIZE, PAYLOAD_SIZE];
	let (raw_first_mixnode_index, surb_header, first_payload_encryption_key) =
		array_refs![surb, RAW_MIXNODE_INDEX_SIZE, HEADER_SIZE, PAYLOAD_ENCRYPTION_KEY_SIZE];

	// Copy the header from the SURB across as-is. We can't really check it; we just have to trust
	// it.
	*header = *surb_header;

	// Force the payload tag
	*array_mut_ref![payload, PAYLOAD_DATA_SIZE, PAYLOAD_TAG_SIZE] = PAYLOAD_TAG;

	// Encrypt the payload. Actually "decrypt" to make decrypt_reply_payload slightly simpler.
	decrypt_payload(payload, first_payload_encryption_key);

	// Return the mixnode index of the first hop from the SURB
	let raw_first_mixnode_index = RawMixnodeIndex::from_le_bytes(*raw_first_mixnode_index);
	raw_first_mixnode_index.try_into().ok()
}

/// Build a Sphinx cover packet. `targets` should not include the first hop. At most one target may
/// be a peer ID; all others should be mixnode indices. Returns the total forwarding delay across
/// all hops.
pub fn build_cover_packet(
	packet: &mut Packet,
	rng: &mut (impl Rng + CryptoRng),
	targets: &[Target],
	their_kx_publics: &[KxPublic],
	id: Option<&CoverId>,
) -> Delay {
	debug_assert_eq!(targets.len() + 1, their_kx_publics.len());
	debug_assert!(their_kx_publics.len() <= MAX_HOPS);

	let (header, payload) = mut_array_refs![packet, HEADER_SIZE, PAYLOAD_SIZE];

	// Build the header
	let mut kx_shared_secrets = ArrayVec::new();
	let total_delay = build_header(
		header,
		&mut kx_shared_secrets,
		rng,
		targets,
		their_kx_publics,
		PacketKind::Cover(id),
	);

	// Randomise the payload. It will be ignored by the destination, but needs to be
	// indistinguishable from a normal encrypted payload.
	rng.fill_bytes(payload);

	total_delay
}
