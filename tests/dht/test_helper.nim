import
  stew/shims/net, bearssl, chronos,
  libp2pdht/discv5/[spr, node, routing_table],
  libp2pdht/discv5/protocol as discv5_protocol,
  libp2p/crypto/crypto,
  libp2p/multiaddress

export net

proc localAddress*(port: int): Address =
  Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(port))

proc initDiscoveryNode*(
    rng: ref BrHmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openArray[SignedPeerRecord] = [],
    localEnrFields: openArray[(string, seq[byte])] = [],
    previousRecord = none[SignedPeerRecord]()):
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
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): Node =
  let
    port = Port(port)
    spr = SignedPeerRecord.init(1, privKey, some(ip), some(port), some(port))
              .expect("Properly intialized private key")
  result = newNode(spr).expect("Properly initialized node")

proc generateNRandomNodes*(rng: ref BrHmacDrbgContext, n: int): seq[Node] =
  var res = newSeq[Node]()
  for i in 1..n:
    let node = generateNode(PrivateKey.random(rng[]).get)
    res.add(node)
  res

proc nodeAndPrivKeyAtDistance*(n: Node, rng: var BrHmacDrbgContext, d: uint32,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): (Node, PrivateKey) =
  while true:
    let pk = PrivateKey.random(rng).get
    let node = generateNode(pk, ip = ip)
    if logDistance(n.id, node.id) == d:
      return (node, pk)

proc nodeAtDistance*(n: Node, rng: var BrHmacDrbgContext, d: uint32,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): Node =
  let (node, _) = n.nodeAndPrivKeyAtDistance(rng, d, ip)
  node

proc nodesAtDistance*(
    n: Node, rng: var BrHmacDrbgContext, d: uint32, amount: int,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): seq[Node] =
  for i in 0..<amount:
    result.add(nodeAtDistance(n, rng, d, ip))

proc nodesAtDistanceUniqueIp*(
    n: Node, rng: var BrHmacDrbgContext, d: uint32, amount: int,
    ip: ValidIpAddress = ValidIpAddress.init("127.0.0.1")): seq[Node] =
  var ta = initTAddress(ip, Port(0))
  for i in 0..<amount:
    ta.inc()
    result.add(nodeAtDistance(n, rng, d, ValidIpAddress.init(ta.address())))

proc addSeenNode*(d: discv5_protocol.Protocol, n: Node): bool =
  # Add it as a seen node, warning: for testing convenience only!
  n.seen = true
  d.addNode(n)

func udpExample*(_: type MultiAddress): MultiAddress =
  ## creates a new udp multiaddress on a random port
  Multiaddress.init("/ip4/0.0.0.0/udp/0")

func udpExamples*(_: type MultiAddress, count: int): seq[MultiAddress] =
  var res: seq[MultiAddress] = @[]
  for i in 1..count:
    res.add Multiaddress.init("/ip4/0.0.0.0/udp/" & $i).get
  return res

proc toSignedPeerRecord*(privKey: crypto.PrivateKey) : SignedPeerRecord =
  ## handle conversion between the two worlds

  let pr = PeerRecord.init(
    peerId = PeerId.init(privKey.getPublicKey.get).get,
    addresses = MultiAddress.udpExamples(3))
  return SignedPeerRecord.init(privKey, pr)
           .expect("Should init SignedPeerRecord with private key")

proc example*(T: type SignedPeerRecord): T =
  let
    rng = crypto.newRng()
    privKey = crypto.PrivateKey.random(rng[]).expect("Valid rng")

  privKey.toSignedPeerRecord
