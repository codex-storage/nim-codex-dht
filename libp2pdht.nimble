# Package

version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "DHT based on the libp2p Kademlia spec"
license       = "MIT"
skipDirs      = @["tests"]


# Dependencies
requires "nim >= 1.2.0",
         "nimcrypto >= 0.5.4 & < 0.6.0",
         "bearssl >= 0.1.5 & < 0.2.0",
         "chronicles >= 0.10.2 & < 0.11.0",
         "chronos >= 3.0.11 & < 3.1.0",
         "eth >= 1.0.0 & < 1.1.0", # to be removed in https://github.com/status-im/nim-libp2p-dht/issues/2
         "libp2p#unstable",
         "metrics",
         "protobufserialization >= 0.2.0 & < 0.3.0",
         "secp256k1 >= 0.5.2 & < 0.6.0",
         "stew#head",
         "stint",
         "asynctest#88ae00ea288c93b23d0111da4868127a1426f39d" # >= 0.3.0 & < 0.4.0"
        #  "testutils >= 0.4.2 & < 0.5.0"
