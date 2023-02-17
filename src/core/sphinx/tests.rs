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

//! Sphinx packet building/peeling tests.

#![cfg(test)]

use super::{
	crypto::{derive_kx_public, derive_kx_shared_secret, gen_kx_secret},
	packet::HEADER_SIZE,
	*,
};
use arrayref::array_mut_ref;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};

fn gen_mixnode_index(rng: &mut impl Rng) -> MixnodeIndex {
	rng.gen_range(0, MAX_MIXNODE_INDEX + 1).try_into().unwrap()
}

fn gen_targets(rng: &mut impl Rng, num_hops: usize) -> Vec<Target> {
	let peer_id_i = rng.gen_range(0, num_hops - 1);
	(0..num_hops - 1)
		.map(|i| {
			if i == peer_id_i {
				Target::PeerId(rng.gen())
			} else {
				Target::MixnodeIndex(gen_mixnode_index(rng))
			}
		})
		.collect()
}

fn gen_their_kx_secrets_and_publics(
	rng: &mut (impl Rng + CryptoRng),
	num_hops: usize,
) -> (Vec<Scalar>, Vec<KxPublic>) {
	(0..num_hops)
		.map(|_i| {
			let secret = gen_kx_secret(&mut *rng);
			let public = derive_kx_public(&secret);
			(secret, public)
		})
		.unzip()
}

fn gen_payload_data(rng: &mut impl Rng) -> PayloadData {
	let mut data = [0; PAYLOAD_DATA_SIZE];
	rng.fill_bytes(&mut data);
	data
}

#[test]
fn basic_operation() {
	let mut rng = rand::thread_rng();

	let num_hops = rng.gen_range(MAX_HOPS - 1, MAX_HOPS + 1);
	let targets = gen_targets(&mut rng, num_hops);
	let (their_kx_secrets, their_kx_publics) = gen_their_kx_secrets_and_publics(&mut rng, num_hops);
	let payload_data = gen_payload_data(&mut rng);

	let mut packet = [0; PACKET_SIZE];
	*mut_payload_data(&mut packet) = payload_data;
	let expected_total_delay =
		complete_request_packet(&mut packet, &mut rng, &targets, &their_kx_publics);

	let mut total_delay = Delay::zero();
	for (expected_target, their_kx_secret) in
		targets.iter().map(Some).chain(std::iter::once(None)).zip(&their_kx_secrets)
	{
		let kx_shared_secret = derive_kx_shared_secret(kx_public(&packet), their_kx_secret);

		let mut out = [0; PACKET_SIZE];
		let action = peel(&mut out, &packet, &kx_shared_secret).unwrap();

		let target = match &action {
			Action::ForwardTo { target, delay } => {
				total_delay += *delay;
				packet = out;
				Some(target)
			},
			Action::DeliverRequest => {
				assert_eq!(out[..PAYLOAD_DATA_SIZE], payload_data);
				None
			},
			Action::DeliverReply { .. } => panic!("Did not expect deliver reply action"),
			Action::DeliverCover { .. } => panic!("Did not expect deliver cover action"),
		};
		assert_eq!(target, expected_target);
	}

	assert_eq!(total_delay, expected_total_delay);
}

#[test]
fn bad_mac() {
	let mut rng = rand::thread_rng();

	let targets = [];
	let (their_kx_secrets, their_kx_publics) = gen_their_kx_secrets_and_publics(&mut rng, 1);

	let mut packet = [0; PACKET_SIZE];
	complete_request_packet(&mut packet, &mut rng, &targets, &their_kx_publics);

	let kx_shared_secret =
		derive_kx_shared_secret(kx_public(&packet), their_kx_secrets.first().unwrap());

	let mut out = [0; PACKET_SIZE];

	// Corrupt the header, MAC check should fail
	packet[HEADER_SIZE - 1] ^= 1;
	assert_eq!(peel(&mut out, &packet, &kx_shared_secret), Err(PeelErr::Mac));

	// Fix the header, peel should succeed
	packet[HEADER_SIZE - 1] ^= 1;
	assert_eq!(peel(&mut out, &packet, &kx_shared_secret), Ok(Action::DeliverRequest));
}

#[test]
fn bad_payload_tag() {
	let mut rng = rand::thread_rng();

	let targets = [];
	let (their_kx_secrets, their_kx_publics) = gen_their_kx_secrets_and_publics(&mut rng, 1);
	let payload_data = gen_payload_data(&mut rng);

	let mut packet = [0; PACKET_SIZE];
	*mut_payload_data(&mut packet) = payload_data;
	complete_request_packet(&mut packet, &mut rng, &targets, &their_kx_publics);

	let kx_shared_secret =
		derive_kx_shared_secret(kx_public(&packet), their_kx_secrets.first().unwrap());

	let mut out = [0; PACKET_SIZE];

	// Corrupt the payload, tag check should fail
	packet[HEADER_SIZE] ^= 1;
	assert_eq!(peel(&mut out, &packet, &kx_shared_secret), Err(PeelErr::PayloadTag));

	// Fix the payload, peel should succeed
	packet[HEADER_SIZE] ^= 1;
	assert_eq!(peel(&mut out, &packet, &kx_shared_secret), Ok(Action::DeliverRequest));
	assert_eq!(out[..PAYLOAD_DATA_SIZE], payload_data);
}

#[test]
fn surb() {
	let mut rng = rand::thread_rng();

	let num_hops = rng.gen_range(MAX_HOPS - 1, MAX_HOPS + 1);
	let first_mixnode_index = gen_mixnode_index(&mut rng);
	let targets = gen_targets(&mut rng, num_hops);
	let (their_kx_secrets, their_kx_publics) = gen_their_kx_secrets_and_publics(&mut rng, num_hops);
	let expected_surb_id = rng.gen();
	let payload_data = gen_payload_data(&mut rng);

	let mut surb = [0; SURB_SIZE];
	let mut payload_encryption_keys = SurbPayloadEncryptionKeys::new();
	let expected_total_delay = build_surb(
		&mut surb,
		&mut payload_encryption_keys,
		&mut rng,
		first_mixnode_index,
		&targets,
		&their_kx_publics,
		&expected_surb_id,
	);

	let mut packet = [0; PACKET_SIZE];
	*mut_payload_data(&mut packet) = payload_data;
	assert_eq!(complete_reply_packet(&mut packet, &surb), Some(first_mixnode_index));

	let mut total_delay = Delay::zero();
	for (expected_target, their_kx_secret) in
		targets.iter().map(Some).chain(std::iter::once(None)).zip(&their_kx_secrets)
	{
		let kx_shared_secret = derive_kx_shared_secret(kx_public(&packet), their_kx_secret);

		let mut out = [0; PACKET_SIZE];
		let action = peel(&mut out, &packet, &kx_shared_secret).unwrap();

		let target = match &action {
			Action::ForwardTo { target, delay } => {
				total_delay += *delay;
				packet = out;
				Some(target)
			},
			Action::DeliverReply { surb_id } => {
				assert_eq!(surb_id, &expected_surb_id);
				decrypt_reply_payload(
					array_mut_ref![out, 0, PAYLOAD_SIZE],
					&payload_encryption_keys,
				)
				.unwrap();
				assert_eq!(out[..PAYLOAD_DATA_SIZE], payload_data);
				None
			},
			Action::DeliverRequest => panic!("Did not expect deliver request action"),
			Action::DeliverCover { .. } => panic!("Did not expect deliver cover action"),
		};
		assert_eq!(target, expected_target);
	}

	assert_eq!(total_delay, expected_total_delay);
}
