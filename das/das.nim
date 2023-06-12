import
  std/[options, sequtils, random, math],
  asynctest,
  bearssl/rand,
  chronicles,
  chronos,
  nimcrypto,
  libp2p/crypto/[crypto, secp],
  libp2p/[multiaddress, multicodec, multihash, routing_record, signed_envelope],
  libp2pdht/dht,
  libp2pdht/discv5/crypto as dhtcrypto,
  libp2pdht/discv5/protocol as discv5_protocol,
  stew/byteutils,
  tests/dht/test_helper

logScope:
  topics = "DAS emulator"

proc bootstrapNodes(
    nodecount: int,
    bootnodes: seq[SignedPeerRecord],
    rng = newRng(),
    delay: int = 0
  ) : Future[seq[(discv5_protocol.Protocol, PrivateKey)]] {.async.} =

  debug "---- STARTING BOOSTRAPS ---"
  for i in 0..<nodecount:
    try:
      let privKey = PrivateKey.example(rng)
      let node = initDiscoveryNode(rng, privKey, localAddress(20302 + i), bootnodes)
      await node.start()
      result.add((node, privKey))
      if delay > 0:
        await sleepAsync(chronos.milliseconds(delay))
    except TransportOsError as e:
      echo "skipping node ",i ,":", e.msg

  #await allFutures(result.mapIt(it.bootstrap())) # this waits for bootstrap based on bootENode, which includes bonding with all its ping pongs

proc bootstrapNetwork(
    nodecount: int,
    rng = newRng(),
    delay: int = 0
  ) : Future[seq[(discv5_protocol.Protocol, PrivateKey)]] {.async.} =

  let
    bootNodeKey = PrivateKey.fromHex(
      "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")
      .expect("Valid private key hex")
    bootNodeAddr = localAddress(20301)
    bootNode = initDiscoveryNode(rng, bootNodeKey, bootNodeAddr, @[]) # just a shortcut for new and open

  #waitFor bootNode.bootstrap()  # immediate, since no bootnodes are defined above

  var res = await bootstrapNodes(nodecount - 1,
                           @[bootnode.localNode.record],
                           rng,
                           delay)
  res.insert((bootNode, bootNodeKey), 0)
  return res

proc toNodeId(data: openArray[byte]): NodeId =
  readUintBE[256](keccak256.digest(data).data)

proc segmentData(s: int, segmentsize: int) : seq[byte] =
  result = newSeq[byte](segmentsize)
  var
    r = s
    i = 0
  while r > 0:
    assert(i<segmentsize)
    result[i] = byte(r mod 256)
    r = r div 256
    i+=1

proc sample(s: Slice[int], len: int): seq[int] =
    # random sample without replacement
    # TODO: not the best for small len
  assert s.a <= s.b
  var all = s.b - s.a + 1
  var count = len
  if len >= all div 10: # add better algo selector
    var generated = newSeq[bool](all) # Initialized to false.
    while count != 0:
      let n = rand(s)
      if not generated[n - s.a]:
        generated[n - s.a] = true
        result.add n
        dec count
  else:
    while count != 0:
      let n = rand(s)
      if not (n in result):
        result.add n
        dec count


when isMainModule:
  proc main() {.async.} =
    let
      nodecount = 5
      delay_pernode = 10 # in millisec
      delay_init = 2*1000 # in millisec
      blocksize = 16
      segmentsize = 10
      samplesize = 3
      upload_timeout = 5.seconds
      sampling_timeout = 5.seconds
    assert(log2(blocksize.float).ceil.int <= segmentsize * 8 )

    var
      rng: ref HmacDrbgContext
      nodes: seq[(discv5_protocol.Protocol, PrivateKey)]
      node0: discv5_protocol.Protocol
      privKey0: PrivateKey
      signedPeerRec0: SignedPeerRecord
      peerRec0: PeerRecord
      segmentIDs = newSeq[NodeId](blocksize)

    # start network
    rng = newRng()
    nodes = await bootstrapNetwork(nodecount=nodecount, delay=delay_pernode)
    (node0, privKey0) = nodes[0]
    signedPeerRec0 = privKey0.toSignedPeerRecord
    peerRec0 = signedPeerRec0.data

    # wait for network to settle
    await sleepAsync(chronos.milliseconds(delay_init))

    # generate block and push data
    info "starting upload to DHT"
    let startTime = Moment.now()
    var futs = newSeq[Future[seq[Node]]]()
    for s in 0 ..< blocksize:
      let
        segment = segmentData(s, segmentsize)
        key = toNodeId(segment)

      segmentIDs[s] = key

      futs.add(node0.addValue(key, segment))

    let pass = await allFutures(futs).withTimeout(upload_timeout)
    info "uploaded to DHT", by = 0, pass, time = Moment.now() - startTime

    # sample
    for n in 1 ..< nodecount:
      let startTime = Moment.now()
      var futs = newSeq[Future[DiscResult[seq[byte]]]]()

      let sample = sample(0 ..< blocksize, samplesize)
      for s in sample:
        let fut = nodes[n][0].getValue(segmentIDs[s])
        futs.add(fut)

      # test is passed if all segments are retrieved in time
      let pass = await allFutures(futs).withTimeout(sampling_timeout)
      var passcount: int
      for f in futs:
        if f.finished():
          passcount += 1

      info "sample", by = n, pass, cnt = passcount, time = Moment.now() - startTime

  waitfor main()

# proc teardownAll() =
#     for (n, _) in nodes: # if last test is enabled, we need nodes[1..^1] here
#       await n.closeWait()


