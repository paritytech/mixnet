# Parity Mix Network

## Overview

This crate implements the core logic for a [Substrate Mix
Network](https://paritytech.github.io/mixnet-spec/) node. It does _not_ provide a full node
implementation; the following parts must be provided by the crate user:

- Networking. This crate is mostly network-agnostic.
- Blockchain integration. This crate expects to be provided with the current session index, phase,
  and mixnodes.
- Request/reply handling. This crate treats request and reply payloads as opaque blobs.

## Modules

The core mixnet logic lives in the `core` module and may be used on its own. The `request_manager`
and `reply_manager` modules provide a very simple reliable delivery layer.
