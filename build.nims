import std / strutils

switch("define", "libp2p_pki_schemes=secp256k1")

task testAll, "Run DHT tests":
  exec "nim c -r tests/testAll.nim"

task test, "Run DHT tests":
  exec "nim c -r -d:testsAll --verbosity:0 tests/testAllParallel.nim"

task testPart1, "Run DHT tests A":
  exec "nim c -r -d:testsPart1 tests/testAllParallel.nim"

task testPart2, "Run DHT tests B":
  exec "nim c -r -d:testsPart2 tests/testAllParallel.nim"

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
  exec("$(which bash) -c 'shopt -s globstar; ls $(pwd)/codexdht/{*,**/*}.nim'")
  exec("$(which bash) -c 'shopt -s globstar; lcov --extract coverage/coverage.info  $(pwd)/codexdht/{*,**/*}.nim --output-file coverage/coverage.f.info'")
  echo "Generating HTML coverage report"
  exec("genhtml coverage/coverage.f.info --output-directory coverage/report")
  echo "Opening HTML coverage report in browser..."
  exec("open coverage/report/index.html")

