# A DHT implementation for Codex

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](#stability)
[![CI (GitHub Actions)](https://github.com/codex-storage/nim-codex-dht/workflows/CI/badge.svg?branch=master)](https://github.com/codex-storage/nim-codex-dht/actions/workflows/ci.yml?query=workflow%3ACI+branch%3Amaster)
[![codecov](https://codecov.io/gh/codex-storage/nim-codex-dht/branch/master/graph/badge.svg?token=tlmMJgU4l7)](https://codecov.io/gh/codex-storage/nim-codex-dht)

This DHT implementation is aiming to provide a DHT for Codex with the following properties
* flexible secure transport usage with
  * fast UDP based operation
  * eventual fallback to TCP-based operation (maybe though libp2p)
  * eventually support operation on top of libp2p
* flexible message encoding that plays well with the above transports
* provide node lookup, content storage/lookup, and provider storage/lookup operations
  * roughly follow the libp2p-dht specifications from https://github.com/libp2p/specs/tree/master/kad-dht
  * eventually provide compatibility mode with the above specs

Current implementation is based on nim-eth's Discovery v5 implementation.

Base files were copied from [`status-im/nim-eth@779d767b024175a51cf74c79ec7513301ebe2f46`](https://github.com/status-im/nim-eth/commit/779d767b024175a51cf74c79ec7513301ebe2f46)

## Building

This repo is setup to use Nimble lockfiles. This requires Nimble 0.14+ which isn't installed by default when this was written. If `nimble -v` reports `0.13.x` then you will need to install Nimble 0.14. Note that using Nimble 0.14 changes how Nimble behaves! 

Nimble 0.14 can be install by: 

```sh
nimble install nimble@0.14.2
```

After this you can setup your Nimble environment. Note that this will build the pinned version of Nim! The first run can take ~15 minutes.

```sh
nimble setup # creates a nimble.paths used for rest of Nimble commands
nimble testAll
```

You can also run tasks directly:

```sh
nim testAll
```
