# Package

version       = "0.3.1"
author        = "Status Research & Development GmbH"
description   = "DHT based on the libp2p Kademlia spec"
license       = "MIT"
skipDirs      = @["tests"]


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

task testAll, "Run DHT tests":
  exec "nim c -r tests/testAll.nim"

task test, "Run DHT tests":
  exec "nim c -r --verbosity:0 tests/testAllParallel.nim"

# task coverage, "generates code coverage report":
#   var (output, exitCode) = gorgeEx("which lcov")
#   if exitCode != 0:
#     echo ""
#     echo "  ************************** ⛔️ ERROR ⛔️ **************************"
#     echo "  **                                                             **"
#     echo "  **   ERROR: lcov not found, it must be installed to run code   **"
#     echo "  **   coverage locally                                          **"
#     echo "  **                                                             **"
#     echo "  *****************************************************************"
#     echo ""
#     quit 1

#   (output, exitCode) = gorgeEx("gcov --version")
#   if output.contains("Apple LLVM"):
#     echo ""
#     echo "  ************************* ⚠️  WARNING ⚠️  *************************"
#     echo "  **                                                             **"
#     echo "  **   WARNING: Using Apple's llvm-cov in place of gcov, which   **"
#     echo "  **   emulates an old version of gcov (4.2.0) and therefore     **"
#     echo "  **   coverage results will differ than those on CI (which      **"
#     echo "  **   uses a much newer version of gcov).                       **"
#     echo "  **                                                             **"
#     echo "  *****************************************************************"
#     echo ""

#   exec("nimble --verbose test --opt:speed -d:debug --verbosity:0 --hints:off --lineDir:on -d:chronicles_log_level=INFO --nimcache:nimcache --passC:-fprofile-arcs --passC:-ftest-coverage --passL:-fprofile-arcs --passL:-ftest-coverage")
#   exec("cd nimcache; rm *.c; cd ..")
#   mkDir("coverage")
#   exec("lcov --capture --directory nimcache --output-file coverage/coverage.info")
#   exec("$(which bash) -c 'shopt -s globstar; ls $(pwd)/codexdht/{*,**/*}.nim'")
#   exec("$(which bash) -c 'shopt -s globstar; lcov --extract coverage/coverage.info  $(pwd)/codexdht/{*,**/*}.nim --output-file coverage/coverage.f.info'")
#   echo "Generating HTML coverage report"
#   exec("genhtml coverage/coverage.f.info --output-directory coverage/report")
#   echo "Opening HTML coverage report in browser..."
#   exec("open coverage/report/index.html")

