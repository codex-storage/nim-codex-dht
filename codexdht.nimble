# Package

version       = "0.6.4"
author        = "Status Research & Development GmbH"
description   = "DHT based on Eth discv5 implementation"
license       = "MIT"
skipDirs      = @["tests"]

# Dependencies
requires "nim >= 2.2.4 & < 3.0.0"
requires "secp256k1 >= 0.6.0 & < 0.7.0"
requires "nimcrypto >= 0.6.2 & < 0.8.0"
requires "bearssl >= 0.2.5 & < 0.3.0"
requires "chronicles >= 0.11.2 & < 0.13.0"
requires "chronos >= 4.2.2 & < 4.4.0"
requires "libp2p >= 2.2.0 & < 3.0.0"
requires "protobuf_serialization >= 0.5.3 & < 0.6.0"
requires "metrics >= 0.2.2 & < 0.3.0"
requires "stew >= 0.4.2"
requires "stint >= 0.8.1 & < 0.9.0"
requires "https://github.com/logos-storage/nim-datastore >= 0.2.1 & < 0.3.0"
requires "questionable >= 0.10.15 & < 0.11.0"
requires "leveldbstatic >= 0.2.1 & < 0.3.0"

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
