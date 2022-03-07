#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.used.}

import
  std/options,
  std/sequtils,
  chronos, stew/byteutils, nimcrypto, asynctest,
  eth/keys,
  libp2pdht/dht,
  chronicles,
  libp2pdht/discv5/protocol as discv5_protocol,
  test_helper,
  libp2p/crypto/crypto,
  libp2p/crypto/secp,
  libp2p/routing_record,
  libp2p/multihash,
  libp2p/multicodec,
  libp2p/signed_envelope



# suite "Providers Tests: node alone":

proc initProvidersNode(
    rng: ref BrHmacDrbgContext,
    privKey: keys.PrivateKey,
    address: Address,
    bootstrapRecords: openArray[Record] = []):
    ProvidersProtocol =

  let d = initDiscoveryNode(rng, privKey, address, bootstrapRecords)
  newProvidersProtocol(d)

proc toSignedPeerRecord(privKey: crypto.PrivateKey) : SignedPeerRecord =
  ## handle conversion between the two worlds

  let pr = PeerRecord.init(
    peerId = PeerId.init(privKey.getPublicKey.get).get,
    seqNo = 0,
    addresses = @[])
  return SignedPeerRecord.init(privKey, pr).expect("Should init SignedPeerRecord with private key")
  # trace "IDs", discNodeId, digest, mh, peerId=result.peerId.hex

proc bootstrapNodes(nodecount: int, bootnodes: openArray[Record], rng = keys.newRng()) : seq[(ProvidersProtocol, keys.PrivateKey)] =

    for i in 0..<nodecount:
      let privKey = keys.PrivateKey.random(rng[])
      let node = initProvidersNode(rng, privKey, localAddress(20302 + i), bootnodes)
      node.discovery.start()
      result.add((node, privKey))
    debug "---- STARTING BOOSTRAPS ---"

    #await allFutures(result.mapIt(it.bootstrap())) # this waits for bootstrap based on bootENode, which includes bonding with all its ping pongs

proc bootstrapNetwork(nodecount: int, rng = keys.newRng()) : seq[(ProvidersProtocol, keys.PrivateKey)] =
  let
    privKey = keys.PrivateKey.fromHex(
      "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
    bootNodeKey = keys.PrivateKey.fromHex(
      "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
    bootNodeAddr = localAddress(20301)
    bootNode = initProvidersNode(rng, bootNodeKey, bootNodeAddr, @[]) # just a shortcut for new and open

  #waitFor bootNode.bootstrap()  # immediate, since no bootnodes are defined above

  result = bootstrapNodes(nodecount - 1, @[bootnode.discovery.localNode.record], rng = rng)
  result.insert((bootNode, privKey), 0)

# TODO: Remove this once we have removed all traces of nim-eth/keys
func pkToPk(pk: keys.PrivateKey) : Option[crypto.PrivateKey] =
  let res = some(crypto.PrivateKey.init((secp.SkPrivateKey)(pk)))
  return res


# suite "Providers Tests":
suite "Providers Tests: node alone":
  var
    rng: ref HmacDrbgContext
    nodes: seq[(ProvidersProtocol, keys.PrivateKey)]
    targetId: NodeId
    node0: ProvidersProtocol
    privKey_keys0: keys.PrivateKey
    privKey0: crypto.PrivateKey
    signedPeerRec0: SignedPeerRecord
    peerRec0: PeerRecord

  setupAll:
    rng = keys.newRng()
    nodes = bootstrapNetwork(nodecount=1)
    targetId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey)
    (node0, privKey_keys0) = nodes[0]
    privKey0 = privKey_keys0.pkToPk.get
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

  teardownAll:
    for (n, _) in nodes:
      await n.discovery.closeWait()
    await sleepAsync(chronos.seconds(3))


  test "Node in isolation should store":
    debug "---- ADDING PROVIDERS ---", nodes = nodes.len
    let addedTo = await node0.addProvider(targetId, signedPeerRec0)
    debug "Provider added to: ", addedTo

    debug "---- STARTING CHECKS ---"
    check (addedTo.len == 1)
    check (addedTo[0].id == node0.discovery.localNode.id)
    check (node0.getProvidersLocal(targetId)[0].data.peerId == peerRec0.peerId)

  test "Node in isolation should retrieve":

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providers = await node0.getProviders(targetId)
    debug "Providers:", providers

    debug "---- STARTING CHECKS ---"
    check (providers.len > 0 and providers[0].data.peerId == peerRec0.peerId)

  test "Should not retrieve bogus":

    let bogusId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey)

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providers = await node0.getProviders(bogusId)
    debug "Providers:", providers

    debug "---- STARTING CHECKS ---"
    check (providers.len == 0)


suite "Providers Tests: two nodes":

  var
    rng: ref HmacDrbgContext
    nodes: seq[(ProvidersProtocol, keys.PrivateKey)]
    targetId: NodeId
    node0: ProvidersProtocol
    privKey_keys0: keys.PrivateKey
    privKey0: crypto.PrivateKey
    signedPeerRec0: SignedPeerRecord
    peerRec0: PeerRecord

  setupAll:
    rng = keys.newRng()
    nodes = bootstrapNetwork(nodecount=2)
    targetId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey)
    (node0, privKey_keys0) = nodes[0]
    privKey0 = privKey_keys0.pkToPk.get
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

  teardownAll:
    for (n, _) in nodes:
      await n.discovery.closeWait()
    await sleepAsync(chronos.seconds(3))

  test "2 nodes, store and retrieve from same":

    debug "---- ADDING PROVIDERS ---"
    let addedTo = await node0.addProvider(targetId, signedPeerRec0)
    debug "Provider added to: ", addedTo

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providers = await node0.getProviders(targetId)
    debug "Providers:", providers

    debug "---- STARTING CHECKS ---"
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)

  test "2 nodes, retrieve from other":
    debug "---- STARTING PROVIDERS LOOKUP ---"
    let (node1, _) = nodes[1]
    let providers = await node1.getProviders(targetId)
    debug "Providers:", providers

    debug "---- STARTING CHECKS ---"
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)



suite "Providers Tests: 20 nodes":

  var
    rng: ref HmacDrbgContext
    nodes: seq[(ProvidersProtocol, keys.PrivateKey)]
    targetId: NodeId
    node0: ProvidersProtocol
    privKey_keys0: keys.PrivateKey
    privKey0: crypto.PrivateKey
    signedPeerRec0: SignedPeerRecord
    peerRec0: PeerRecord

  setupAll:
    rng = keys.newRng()
    nodes = bootstrapNetwork(nodecount=20)
    targetId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey)
    (node0, privKey_keys0) = nodes[0]
    privKey0 = privKey_keys0.pkToPk.get
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

    await sleepAsync(chronos.seconds(15))

  teardownAll:
    for (n, _) in nodes: # if last test is enabled, we need nodes[1..^1] here
      await n.discovery.closeWait()

  test "20 nodes, store and retrieve from same":

    debug "---- ADDING PROVIDERS ---"
    let addedTo = await node0.addProvider(targetId, signedPeerRec0)
    debug "Provider added to: ", addedTo

    debug "---- STARTING PROVIDERS LOOKUP ---"
    let providers = await node0.getProviders(targetId)
    debug "Providers:", providers

    debug "---- STARTING CHECKS ---"
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)

  test "20 nodes, retrieve from other":
    debug "---- STARTING PROVIDERS LOOKUP ---"
    let (node19, _) = nodes[^2]
    let providers = await node19.getProviders(targetId)
    debug "Providers:", providers

    debug "---- STARTING CHECKS ---"
    check (providers.len == 1 and providers[0].data.peerId == peerRec0.peerId)

  # test "20 nodes, retieve after bootnode dies":
  #   # TODO: currently this is not working even with a 2 minute timeout
  #   debug "---- KILLING BOOTSTRAP NODE ---"
  #   await nodes[0].discovery.closeWait()

  #   debug "---- STARTING PROVIDERS LOOKUP ---"
  #   let providers = await nodes[^2].getProviders(targetId)
  #   debug "Providers:", providers

  #   debug "---- STARTING CHECKS ---"
  #   check (providers.len == 1 and providers[0].peerId == nodes[0].toPeerRecord.peerId)
