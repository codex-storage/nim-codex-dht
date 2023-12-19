# Package

version       = "0.4.0"
author        = "Status Research & Development GmbH"
description   = "DHT based on Eth discv5 implementation"
license       = "MIT"
skipDirs      = @["tests"]
installFiles  = @["build.nims"]

# Dependencies
requires "nim >= 1.6.16"
requires "secp256k1#2acbbdcc0e63002a013fff49f015708522875832" # >= 0.5.2 & < 0.6.0
requires "protobuf_serialization" # >= 0.2.0 & < 0.3.0
requires "nimcrypto == 0.5.4"
requires "bearssl#head"
requires "chronicles >= 0.10.2 & < 0.11.0"
requires "chronos#c41599a" #  >= 3.0.11 & < 3.1.0
requires "libp2p#unstable"
requires "metrics"
requires "stew#head"
requires "stint"
requires "asynctest <= 0.4.3"
requires "https://github.com/codex-storage/nim-datastore#head"
requires "questionable"

include "build.nims"
