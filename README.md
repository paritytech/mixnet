# Parity Mix Network

## Overview

The mixnet design is loosely based on
[Loopix](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-piotrowska.pdf). The
packet format is based on
[Sphinx](http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/sphinx-eprint.pdf).

[Protocol documentation.](https://github.com/zdave-parity/mixnet-spec/blob/main/src/SUMMARY.md)

# Implementatin details.

Graceful transition between sessions with different topologies is supported, but the transition
phase and topologies must be synchronised between nodes by the crate user.

## Network topology

In the context of a session, the nodes are split into two classes: mixnodes and non-mixnodes.
Mixnodes are responsible for mixing traffic. Non-mixnodes may send requests into the mixnet and
receive replies from the mixnet, but do not mix traffic. Non-mixnodes can join and leave the mixnet
freely, but it is expected that if a node is a mixnode in a session, it will stay connected for the
duration of the session.

The mixnodes for a session are provided by the crate user. They need not be related in any way to
the mixnodes for the previous/following sessions.

Each mixnode in a session has a key-exchange public key which should be known by all other nodes.
The crate user is responsible for broadcasting these public keys. Note that even if the topology is
static, the key-exchange public keys will change and must be rebroadcast every session.

Currently, the mixnodes traversed by a packet are picked at random from the full set of mixnodes
with no constraints. This may change in the future.

## Packet format

Each message is split into multiple fixed size fragments, with each fragment being encapsulated into
a Sphinx packet and routed over a random path within the mixnet. The recipient waits for all
fragments to arrive and is then able to reconstruct the message.

For details on the packet format, see `src/core/sphinx/packet.rs` and `src/core/fragment.rs`.

## Cover traffic

Two types of cover traffic are generated:

- "Drop". Drop cover packets are sent to random mixnodes and are simply dropped on receipt.
- "Loop". Loop cover packets are sent back to the sending node. They are used to gauge network
  health.

Request and reply packets always replace drop cover packets. Loop cover packets are never replaced.

Note that both mixnodes and non-mixnodes generate cover traffic, although typically non-mixnodes
will be configured to generate less traffic (to avoid overwhelming the mixnet when there are a large
number of them).

## Modules

The core mixnet logic lives in the `core` module and may be used on its own. The `request_manager`
and `reply_manager` modules provide a very simple reliable delivery layer.
