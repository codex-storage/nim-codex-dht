when defined(testsPart1) or not defined(testParts):
  import ./dht/test_providers
when defined(testsPart2) or not defined(testParts):
  import ./dht/test_providermngr
when defined(testsPart3) or not defined(testParts):
  import ./discv5/test_discoveryv5
when defined(testsPart4) or not defined(testParts):
  import ./discv5/test_discoveryv5_encoding

{.warning[UnusedImport]: off.}
