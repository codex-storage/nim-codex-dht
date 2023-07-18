# import
#   ./dht/[test_providers, test_providermngr],
#   ./discv5/[test_discoveryv5, test_discoveryv5_encoding]

import std/[os, osproc, strutils]

## we wanna get nimble paths if set
let nimblePaths = getEnv("NIMBLE_PATHS", "").split($PathSep & $PathSep).join(" ")

var cmds: seq[string]
for d in walkDirRec("tests", {pcDir}):
  for (kind, file) in walkDir(d):
    if kind == pcFile and file.endswith(".nim") and file.startsWith("t"):
      cmds.add "nim c " & nimblePaths & " " & file.absolutePath.quoteShell()

when defined(testsPart1):
  cmds = cmds[0..cmds.len div 2 - 1]
when defined(testsPart2):
  cmds = cmds[cmds.len div 2 - 1..<cmds.len]

echo "Running Test Commands: "
for cmd in cmds:
  echo "\t", cmd
echo ""

quit execProcesses(cmds)
