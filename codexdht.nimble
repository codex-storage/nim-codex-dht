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
requires "chronos#e15dc3b41fea95348b58f32244962c1c6df310a7" #  Change to >= 4.0.0 & < 5.0.0 when available
requires "libp2p#unstable"
requires "metrics"
requires "stew#head"
requires "stint"
requires "asynctest >= 0.4.3 & < 0.5.0"
requires "https://github.com/codex-storage/nim-datastore#head"
requires "questionable"

include "build.nims"
 