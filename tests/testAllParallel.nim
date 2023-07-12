# import
#   ./dht/[test_providers, test_providermngr],
#   ./discv5/[test_discoveryv5, test_discoveryv5_encoding]

import osproc

let cmds = [
  "nim c -r --verbosity:0 tests/dht/test_providers.nim",
  "nim c -r --verbosity:0 tests/dht/test_providermngr.nim",
  "nim c -r --verbosity:0 tests/discv5/test_discoveryv5.nim",
  "nim c -r --verbosity:0 tests/discv5/test_discoveryv5_encoding.nim",
]

quit execProcesses(cmds)
