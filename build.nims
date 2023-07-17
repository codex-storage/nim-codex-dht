import std / [os, strutils, sequtils]

when declared(getPathsClause):
  proc nimc(): string = "nim c " & getPathsClause()
else:
  proc nimc(): string = "nim c"

switch("define", "libp2p_pki_schemes=secp256k1")

task testAll, "Run DHT tests":
  exec nimc() & " -r tests/testAll.nim"

task test, "Run DHT tests":
  exec nimc() & " -r -d:testsAll --verbosity:0 tests/testAllParallel.nim"

task testPart1, "Run DHT tests A":
  exec nimc() & " -r -d:testsPart1 tests/testAllParallel.nim"

task testPart2, "Run DHT tests B":
  exec nimc() & " -r -d:testsPart2 tests/testAllParallel.nim"

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

  var nimSrcs = ""
  for f in walkDirRec(".", {pcFile}):
    if f.endswith(".nim"): nimSrcs.add " " & f.absolutePath.quoteShell()

  echo "======== Running Tests ======== "
  exec("nim c -r tests/coverage.nim")
  exec("rm nimcache/*.c")
  rmDir("coverage"); mkDir("coverage")
  echo " ======== Running LCOV ======== "
  exec("lcov --capture --directory nimcache --output-file coverage/coverage.info")
  exec("lcov --extract coverage/coverage.info --output-file coverage/coverage.f.info " & nimSrcs)
  echo " ======== Generating HTML coverage report ======== "
  exec("genhtml coverage/coverage.f.info --output-directory coverage/report ")
  echo " ======== Opening HTML coverage report in browser... ======== "
  if findExe("open") != "":
    exec("open coverage/report/index.html")

