# import
#   ./dht/[test_providers, test_providermngr],
#   ./discv5/[test_discoveryv5, test_discoveryv5_encoding]

import std/[os, osproc, strutils]

when declared(getPathsClause):
  proc nimc(): string = "nim c -r " & getPathsClause()
else:
  proc nimc(): string = "nim c -r "

var cmds: seq[string]
for d in walkDirRec("tests", {pcDir}):
  for (kind, file) in walkDir(d):
    if kind == pcFile and file.endswith(".nim") and file.startsWith("t"):
      cmds.add nimc() & file.absolutePath.quoteShell()

when defined(testsPart1):
  cmds = cmds[0..cmds.len div 2 - 1]
when defined(testsPart2):
  cmds = cmds[cmds.len div 2 - 1..<cmds.len]

echo "Running Test Commands: ", cmds
# quit execProcesses(cmds)
