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
         "libp2p#c7504d2446717a48a79c8b15e0f21bbfc84957ba",
         "metrics",
         "protobufserialization >= 0.2.0 & < 0.3.0",
         "secp256k1 >= 0.5.2 & < 0.6.0",
         "stew#head",
         "stint",
         "asynctest >= 0.3.1 & < 0.4.0"

task coverage, "generates code coverage report":
  var (output, exitCode) = gorgeEx("which lcov")
  if exitCode != 0:
    echo ""
    echo "  ************************** ⛔️ ERROR ⛔️ **************************"
    echo "  **                                                             **"
    echo "  **   ERROR: lcov not found, it must be installed to run code   **"
    echo "  **   coverage locally                                          **"
    echo "  **                                                             **"
    echo "  *****************************************************************"
    echo ""
    quit 1

  (output, exitCode) = gorgeEx("gcov --version")
  if output.contains("Apple LLVM"):
    echo ""
    echo "  ************************* ⚠️  WARNING ⚠️  *************************"
    echo "  **                                                             **"
    echo "  **   WARNING: Using Apple's llvm-cov in place of gcov, which   **"
    echo "  **   emulates an old version of gcov (4.2.0) and therefore     **"
    echo "  **   coverage results will differ than those on CI (which      **"
    echo "  **   uses a much newer version of gcov).                       **"
    echo "  **                                                             **"
    echo "  *****************************************************************"
    echo ""

  exec("nimble --verbose test --opt:speed -d:debug --verbosity:0 --hints:off --lineDir:on -d:chronicles_log_level=INFO --nimcache:nimcache --passC:-fprofile-arcs --passC:-ftest-coverage --passL:-fprofile-arcs --passL:-ftest-coverage")
  exec("cd nimcache; rm *.c; cd ..")
  mkDir("coverage")
  exec("lcov --capture --directory nimcache --output-file coverage/coverage.info")
  exec("$(which bash) -c 'shopt -s globstar; ls $(pwd)/libp2pdht/{*,**/*}.nim'")
  exec("$(which bash) -c 'shopt -s globstar; lcov --extract coverage/coverage.info  $(pwd)/libp2pdht/{*,**/*}.nim --output-file coverage/coverage.f.info'")
  echo "Generating HTML coverage report"
  exec("genhtml coverage/coverage.f.info --output-directory coverage/report")
  echo "Opening HTML coverage report in browser..."
  exec("open coverage/report/index.html")
  
