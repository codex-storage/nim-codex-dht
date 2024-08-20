# Package

version       = "0.4.0"
author        = "Status Research & Development GmbH"
description   = "Tests for Codex DHT"
license       = "MIT"
installFiles  = @["build.nims"]

# Dependencies
requires "asynctest >= 0.5.2 & < 0.6.0" 
requires "unittest2 <= 0.0.9"

include "build.nims"
