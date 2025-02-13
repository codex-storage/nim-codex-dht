# Package

version       = "0.5.0"
author        = "Status Research & Development GmbH"
description   = "DHT based on Eth discv5 implementation"
license       = "MIT"
skipDirs      = @["tests"]

# Dependencies
requires "nim >= 2.0.14 & < 3.0.0"
requires "secp256k1" # >= 0.5.2 & < 0.6.0
requires "protobuf_serialization" # >= 0.2.0 & < 0.3.0
requires "nimcrypto >= 0.5.4"
requires "bearssl == 0.2.5"
requires "chronicles >= 0.10.2 & < 0.11.0"
requires "chronos >= 4.0.3 & < 4.1.0"
requires "libp2p >= 1.5.0 & < 2.0.0"
requires "metrics"
requires "stew >= 0.2.0"
requires "stint >= 0.8.1 & < 0.9.0"
requires "https://github.com/codex-storage/nim-datastore#a969b9799cb7fd2c2511b6820ded00bced141dea"
requires "questionable >= 0.10.15 & < 0.11.0"

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
