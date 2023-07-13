# import
#   ./dht/[test_providers, test_providermngr],
#   ./discv5/[test_discoveryv5, test_discoveryv5_encoding]

import osproc

var cmds: seq[string]

when defined(testsPart1) or defined(testsAll):
  cmds.add [
    "nim c -r --verbosity:0 tests/dht/test_providers.nim",
    "nim c -r --verbosity:0 tests/dht/test_providermngr.nim",
  ]
when defined(testsPart2) or defined(testsAll):
  cmds.add [
    "nim c -r --verbosity:0 tests/discv5/test_discoveryv5.nim",
    "nim c -r --verbosity:0 tests/discv5/test_discoveryv5_encoding.nim",
  ]

echo "CMDS: ", cmds

quit execProcesses(cmds)
