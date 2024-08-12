# Package

version       = "0.4.0"
author        = "Status Research & Development GmbH"
description   = "DHT based on Eth discv5 implementation"
license       = "MIT"
skipDirs      = @["tests"]
installFiles  = @["build.nims"]

# Dependencies
requires "nim >= 1.6.18"
requires "unittest2 <= 0.0.9"
requires "secp256k1#2acbbdcc0e63002a013fff49f015708522875832" # >= 0.5.2 & < 0.6.0
requires "protobuf_serialization" # >= 0.2.0 & < 0.3.0
requires "nimcrypto >= 0.5.4"
requires "bearssl#667b40440a53a58e9f922e29e20818720c62d9ac"
requires "chronicles >= 0.10.2 & < 0.11.0"
requires "chronos#dc3847e4d6733dfc3811454c2a9c384b87343e26"
requires "libp2p#cde5ed7e8ccc3b452878db4c82c6f2f2e70d28f4"
requires "metrics"
requires "stew#head"
requires "stint"
requires "asynctest#12c356672d26053ddc4c1443491e9eee65ec03a2"
requires "https://github.com/codex-storage/nim-datastore#042173085fe6ec035c8159e6c7cbcc149bab5213"
requires "questionable"

include "build.nims"
 