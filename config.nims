import std/os

const currentDir = currentSourcePath()[0 .. ^(len("config.nims") + 1)]

if getEnv("NIMBUS_BUILD_SYSTEM") == "yes" and
   # BEWARE
   # In Nim 1.6, config files are evaluated with a working directory
   # matching where the Nim command was invocated. This means that we
   # must do all file existance checks with full absolute paths:
   system.fileExists(currentDir & "nimbus-build-system.paths"):
  include "nimbus-build-system.paths"

switch("define", "libp2p_pki_schemes=secp256k1")
# begin Nimble config (version 1)
when fileExists("nimble.paths"):
  include "nimble.paths"
# end Nimble config
