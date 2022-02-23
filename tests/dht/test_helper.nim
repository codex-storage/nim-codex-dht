import
  stew/shims/net, bearssl, chronos,
  eth/keys,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol

export net

proc localAddress*(port: int): Address =
  Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(
    rng: ref BrHmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openArray[Record] = [],
    localEnrFields: openArray[(string, seq[byte])] = [],
    previousRecord = none[enr.Record]()):
    discv5_protocol.Protocol =
  # set bucketIpLimit to allow bucket split
  let config = DiscoveryConfig.init(1000, 24, 5)

  let protocol = newProtocol(
    privKey,
    some(address.ip),
    some(address.port), some(address.port),
    bindPort = address.port,
    bootstrapRecords = bootstrapRecords,
    localEnrFields = localEnrFields,
    previousRecord = previousRecord,
    config = config,
    rng = rng)

  protocol.open()

  protocol

proc nodeIdInNodes*(id: NodeId, nodes: openArray[Node]): bool =
  for n in nodes:
    if id == n.id: return true

proc generateNode*(privKey: PrivateKey, port: int = 20302,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1"),
    localEnrFields: openArray[FieldPair] = []): Node =
  let port = Port(port)
  let enr = enr.Record.init(1, privKey, some(ip),
    some(port), some(port), localEnrFields).expect("Properly intialized private key")
  result = newNode(enr).expect("Properly initialized node")

proc generateNRandomNodes*(rng: ref BrHmacDrbgContext, n: int): seq[Node] =
  var res = newSeq[Node]()
  for i in 1..n:
    let node = generateNode(PrivateKey.random(rng[]))
    res.add(node)
  res
