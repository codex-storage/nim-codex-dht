# Package

version       = "0.3.2"
author        = "Status Research & Development GmbH"
description   = "DHT based on Eth discv5 implementation"
license       = "MIT"
skipDirs      = @["tests"]
installFiles  = @["build.nims"]

# Dependencies
requires "nim >= 1.2.0"
requires "secp256k1#b3f38e2795e805743b299dc5d96d332db375b520" # >= 0.5.2 & < 0.6.0
requires "protobuf_serialization#27b400fdf3bd8ce7120ca66fc1de39d3f1a5804a" # >= 0.2.0 & < 0.3.0
requires "nimcrypto == 0.5.4"
requires "bearssl#head"
requires "chronicles >= 0.10.2 & < 0.11.0"
requires "chronos#1394c9e04957928afc1db33d2e0965cfb677a1e0" #  >= 3.0.11 & < 3.1.0
requires "libp2p#unstable"
requires "metrics"
requires "stew#head"
requires "stint"
requires "asynctest >= 0.3.1 & < 0.4.0"
requires "https://github.com/status-im/nim-datastore#head"
requires "questionable"

import "build.nims"
