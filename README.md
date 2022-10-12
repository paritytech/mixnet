Parity Mix Network Specification
====================================

# 1. Abstract

This describes the high level architecture of the mix network meant to 
provide anonymous message delivery service. The main intention for this initial version is to allow anonymous blockchain transaction delivery. 

# 2. System Overview
------------------
The design is losely based on [Loopix](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-piotrowska.pdf) with some simplification listed below. A packet format based on [Sphinx](http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/sphinx-eprint.pdf) is utilized. The specification is based on (Katzenpost)[https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst]

The network is homogeneous. All nodes participate in mix traffic. This implementaton has the following simplifications when compared the Loopix/sphinx design:

* No cover loops are generated, just individual cover messages.
* SURBs are not supported
* Sphinx routing information is simplified to a fixed structure instead of a list of routing commands.
* No replay protection is implemented.

# 3. Network Topology

Network topology is defined externally. The user should implement `Topology` trait 
the defines the relations between nodes and provide access to public keys. 

# 4. Packet Format Overview

Each message is split into multiple fixed size fragments, with each fragment being encapsulated into Sphinx packets and routed over random paths within the mix network. The recipient waits for all fragments to arrive and is then able to reconstruct the message.

TODO: detaild sphinx packet specification

# 5. Mix Protocol Operation

The protocol is implemented as `libp2p::Behaviour` module that can plug into libp2p stack. It implements the "mixnet" protocol. Connections are driven externally and must match the topology reported with the `Topology` trait. Once connection is established peers exhange a handshake that contains the mixing public key. This key is used as fallback if no topology is specified. After that, node start listening for incoming message. For each message the node tries to unwrap a single layer of Sphinx encryption. If the result requires another hop, the unwrapped packet it added to the outbound queue to be sent to the next hop with a delay specified in the packet. If the result is the final payload an attempt is made to reconstruct the full message. If the node has all the fragment of a message it is produced to as an `libp2p::Behaviour` event to the user code. The node generates oubound traffic following Poisson distribution. If no real traffic is to be sent, cover traffic is generated. 

