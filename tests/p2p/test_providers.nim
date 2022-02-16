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
  std/sequtils,
  chronos, stew/byteutils, nimcrypto, testutils/unittests,
  eth/keys,
  ../../eth/p2p/providers,
  chronicles,
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol,
  ./discv5_test_helper,
  libp2p/routing_record,
  libp2p/multihash,
  libp2p/multicodec

proc initProvidersNode(
    rng: ref BrHmacDrbgContext,
    privKey: keys.PrivateKey,
    address: Address,
    bootstrapRecords: openArray[Record] = []):
    ProvidersProtocol =

  let d = initDiscoveryNode(rng, privKey, address, bootstrapRecords)
  newProvidersProtocol(d)

proc toPeerRecord(p: ProvidersProtocol) : PeerRecord =
  ## hadle conversion between the two worlds

  #NodeId is a keccak-256 hash created by keccak256.digest and stored as UInt256
  let discNodeId = p.discovery.localNode.id 
  ## get it back to MDigest form
  var digest: MDigest[256]
  digest.data = discNodeId.toBytesBE
  ## get into a MultiHash
  var mh = MultiHash.init(multiCodec("keccak-256"), digest).orError(HashError).get()
  result = PeerRecord.init(
    peerId = PeerId.init(mh.data.buffer).get,
    seqNo = 0,
    addresses = @[])

proc bootstrapNodes(nodecount: int, bootnodes: openArray[Record], rng = keys.newRng()) : seq[ProvidersProtocol] =

    for i in 0..<nodecount:
      let node = initProvidersNode(rng, keys.PrivateKey.random(rng[]), localAddress(20302 + i), bootnodes)
      node.discovery.start()
      result.add(node)
    debug "---- STARTING BOOSTRAPS ---"

    #await allFutures(result.mapIt(it.bootstrap())) # this waits for bootstrap based on bootENode, which includes bonding with all its ping pongs

proc bootstrapNetwork(nodecount: int, rng = keys.newRng()) : seq[ProvidersProtocol] =
  let
    bootNodeKey = keys.PrivateKey.fromHex(
      "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]
    bootNodeAddr = localAddress(20301)
    bootNode = initProvidersNode(rng, bootNodeKey, bootNodeAddr, @[]) # just a shortcut for new and open

  #waitFor bootNode.bootstrap()  # immediate, since no bootnodes are defined above
  
  result = bootstrapNodes(nodecount - 1, @[bootnode.discovery.localNode.record], rng = rng)
  result.insert(bootNode, 0)


suite "Providers Tests: node alone":

  asyncTest "node alone":
    let
      rng = keys.newRng()
      nodes = bootstrapNetwork(nodecount=1)
      targetId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey)

    asyncTest "Node in isolation should store":

      debug "---- ADDING PROVIDERS ---"
      let addedTo = await nodes[0].addProvider(targetId, nodes[0].toPeerRecord)
      debug "Provider added to: ", addedTo

      debug "---- STARTING CHECKS ---"
      check (addedTo.len == 1)
      check (addedTo[0].id == nodes[0].discovery.localNode.id)
      check (nodes[0].getProvidersLocal(targetId)[0].peerId == nodes[0].toPeerRecord.peerId)

    asyncTest "Node in isolation should retrieve":

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len > 0 and providers[0].peerId == nodes[0].toPeerRecord.peerId)

    asyncTest "Should not retrieve bogus":

      let bogusId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey)
 
      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(bogusId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 0)

    for n in nodes:
      await n.discovery.closeWait()
    await sleepAsync(chronos.seconds(3))

  asyncTest "Providers Tests: two nodes":
    let
      rng = keys.newRng()
      nodes = bootstrapNetwork(nodecount=2)
      targetId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey) 

    asyncTest "2 nodes, store and retieve from same":

      debug "---- ADDING PROVIDERS ---"
      let addedTo = await nodes[0].addProvider(targetId, nodes[0].toPeerRecord)
      debug "Provider added to: ", addedTo

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].peerId == nodes[0].toPeerRecord.peerId)

    asyncTest "2 nodes, retieve from other":
      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[1].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].peerId == nodes[0].toPeerRecord.peerId)

    for n in nodes:
      await n.discovery.closeWait()
    await sleepAsync(chronos.seconds(3))

  asyncTest "Providers Tests: 20 nodes":
    let
      rng = keys.newRng()
      nodes = bootstrapNetwork(nodecount=20)
      targetId = toNodeId(keys.PrivateKey.random(rng[]).toPublicKey) 
    await sleepAsync(chronos.seconds(5))

    asyncTest "20 nodes, store and retieve from same":

      debug "---- ADDING PROVIDERS ---"
      let addedTo = await nodes[0].addProvider(targetId, nodes[0].toPeerRecord)
      debug "Provider added to: ", addedTo

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[0].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].peerId == nodes[0].toPeerRecord.peerId)

    asyncTest "20 nodes, retieve from other":
      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[^1].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].peerId == nodes[0].toPeerRecord.peerId)

    asyncTest "20 nodes, retieve after bootnode dies":
      debug "---- KILLING BOOTSTRAP NODE ---"
      await nodes[0].discovery.closeWait()

      debug "---- STARTING PROVIDERS LOOKUP ---"
      let providers = await nodes[^2].getProviders(targetId)
      debug "Providers:", providers

      debug "---- STARTING CHECKS ---"
      check (providers.len == 1 and providers[0].peerId == nodes[0].toPeerRecord.peerId)

    for n in nodes[1..^1]:
      await n.discovery.closeWait()
