# Package

version       = "0.4.0"
author        = "Status Research & Development GmbH"
description   = "DHT based on Eth discv5 implementation"
license       = "MIT"
skipDirs      = @["tests"]

# Dependencies
requires "secp256k1#2acbbdcc0e63002a013fff49f015708522875832" # >= 0.5.2 & < 0.6.0
requires "protobuf_serialization" # >= 0.2.0 & < 0.3.0
requires "nimcrypto >= 0.5.4"
requires "bearssl == 0.2.5"
requires "chronicles >= 0.10.2 & < 0.11.0"
requires "chronos >= 4.0.3 & < 4.1.0"
requires "libp2p == 1.5.0"
requires "metrics"
requires "stew#head"
requires "stint"
requires "https://github.com/codex-storage/nim-datastore >= 0.1.1 & < 0.2.0"
requires "questionable"

task testAll, "Run all test suites":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble testAll"

task test, "Run the test suite":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble test"

task testPart1, "Run the test suite part 1":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble testPart1"

task testPart2, "Run the test suite part 2":
  exec "nimble install -d -y"
  withDir "tests":
    exec "nimble testPart2"
