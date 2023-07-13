import std/os

const currentDir = currentSourcePath()[0 .. ^(len("config.nims") + 1)]

switch("define", "libp2p_pki_schemes=secp256k1")

task testAll, "Run DHT tests":
  exec "nim c -r tests/testAll.nim"

task test, "Run DHT tests":
  exec "nim c -r --verbosity:0 tests/testAllParallel.nim"

when getEnv("NIMBUS_BUILD_SYSTEM") == "yes" and
    # BEWARE
    # In Nim 1.6, config files are evaluated with a working directory
    # matching where the Nim command was invocated. This means that we
    # must do all file existance checks with full absolute paths:
    system.fileExists(currentDir & "nimbus-build-system.paths"):
  echo "Using Nimbus Paths"
  include "nimbus-build-system.paths"
elif withDir(thisDir(), system.fileExists("nimble.paths")):
  echo "Using Nimble Paths"

# begin Nimble config (version 2)
--noNimblePath
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
