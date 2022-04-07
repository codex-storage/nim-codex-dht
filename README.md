# A DHT implementation for Dagger

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)](#stability)
[![CI (GitHub Actions)](https://github.com/status-im/nim-libp2p-dht/workflows/CI/badge.svg?branch=main)](https://github.com/status-im/nim-libp2p-dht/actions?query=workflow%3ACI+branch%3Amain)
[![codecov](https://codecov.io/gh/status-im/nim-libp2p-dht/branch/main/graph/badge.svg?token=tlmMJgU4l7)](https://codecov.io/gh/status-im/nim-libp2p-dht)

This DHT implementation is aiming to provide a DHT for Dagger with the following properties
* flexible transport usage with
  * fast UDP based operation
  * fallback to TCP-based operation (maybe though libp2p)
  * support operation on top of libp2p
* flexible message encoding that plays well with the above transports
* provide node lookup, content storage/lookup, and provider storage/lookup operations
  * roughly follow the libp2p-dht specifications from https://github.com/libp2p/specs/tree/master/kad-dht
  * provide compatibility mode with the above specs

Current implementation is based on nim-eth's Discovery v5 implementation.

Base files were copied from [`status-im/nim-eth@779d767b024175a51cf74c79ec7513301ebe2f46`](https://github.com/status-im/nim-eth/commit/779d767b024175a51cf74c79ec7513301ebe2f46)
