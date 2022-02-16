# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronos,
  chronos/timer,
  chronicles,
  std/tables, sequtils,
  stew/byteutils, # toBytes
  ../eth/p2p/discoveryv5/[protocol, node],
  libp2p/routing_record,
  libp2p/protobuf/minprotobuf

type
  ProvidersProtocol* = ref object
    providers: Table[NodeId, seq[PeerRecord]]
    discovery*: protocol.Protocol

  AddProviderMessage* = object
    cId: NodeId
    prov: PeerRecord

  GetProvidersMessage* = object
    cId: NodeId

  ProvidersMessage* = object
    total: uint32
    provs: seq[PeerRecord]

func getField*(pb: ProtoBuffer, field: int,
               nid: var NodeId): ProtoResult[bool] {.inline.} =
  ## Read ``NodeId`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    nid = readUintBE[256](buffer)
    ok(true)

func write*(pb: var ProtoBuffer, field: int, nid: NodeId) =
  ## Write NodeId value ``nodeid`` to object ``pb`` using ProtoBuf's encoding.
  write(pb, field, nid.toBytesBE())

func getField*(pb: ProtoBuffer, field: int,
               pr: var PeerRecord): ProtoResult[bool] {.inline.} =
  ## Read ``NodeId`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    let res2 = PeerRecord.decode(buffer)
    if res2.isOk():
      pr = res2.get()
      ok(true)
    else:
      err(ProtoError.IncorrectBlob)

func write*(pb: var ProtoBuffer, field: int, pr: PeerRecord) =
  ## Write PeerRecord value ``pr`` to object ``pb`` using ProtoBuf's encoding.
  write(pb, field, pr.encode())

proc getRepeatedField*(pb: ProtoBuffer, field: int,
                       value: var seq[PeerRecord]): ProtoResult[bool] {.
     inline.} =
  var items: seq[seq[byte]]
  value.setLen(0)
  let res = ? pb.getRepeatedField(field, items)
  if not(res):
    ok(false)
  else:
    for item in items:
      let ma = PeerRecord.decode(item)
      if ma.isOk():
        value.add(ma.get())
      else:
        value.setLen(0)
        return err(ProtoError.IncorrectBlob)
    ok(true)

proc decode*(
  T: typedesc[AddProviderMessage],
  buffer: openArray[byte]): Result[AddProviderMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = AddProviderMessage()

  ? pb.getRequiredField(1, msg.cId)
  ? pb.getRequiredField(2, msg.prov)

  ok(msg)

proc encode*(msg: AddProviderMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.cId)
  pb.write(2, msg.prov)

  pb.finish()
  pb.buffer

proc addProviderLocal(p: ProvidersProtocol, cId: NodeId, prov: PeerRecord) = 
  trace "adding provider to local db", n=p.discovery.localNode, cId, prov
  p.providers.mgetOrPut(cId, @[]).add(prov)

proc recvAddProvider(p: ProvidersProtocol, nodeId: NodeId, payload: openArray[byte])
    {.raises: [Defect].} =
  #TODO: add checks, add signed version
  let msg = AddProviderMessage.decode(payload).get()
  trace "<<< add_provider ",  src = nodeId, dst = p.discovery.localNode.id, cid = msg.cId, prov=msg.prov
  p.addProviderLocal(msg.cId, msg.prov)
  #TODO: check that CID is reasonably close to our NodeID

const
  protoIdAddProvider = "AP".toBytes()

proc registerAddProvider(p: ProvidersProtocol) =
  proc handler(protocol: TalkProtocol, request: seq[byte], fromId: NodeId, fromUdpAddress: Address): seq[byte]
    {.gcsafe, raises: [Defect].} =
    recvAddProvider(p, fromId, request)
    @[] # talk requires a response

  let protocol = TalkProtocol(protocolHandler: handler)
  discard p.discovery.registerTalkProtocol(protoIdAddProvider, protocol) #TODO: handle error

proc sendAddProvider*(p: ProvidersProtocol, dst: Node, cId: NodeId, pr: PeerRecord) =
  #type NodeDesc = tuple[ip: IpAddress, udpPort, tcpPort: Port, pk: PublicKey]
  let msg = AddProviderMessage(cId: cId, prov: pr)
  discard p.discovery.talkReq(dst, protoIdAddProvider, msg.encode())

proc addProvider*(p: ProvidersProtocol, cId: NodeId, pr: PeerRecord): Future[seq[Node]] {.async.} =
  result = await p.discovery.lookup(cId)
  trace "lookup returned:", result
  # TODO: lookup is sepcified as not returning local, even if that is the closest. Is this OK?
  if result.len == 0:
      result.add(p.discovery.localNode)
  for n in result:
    if n != p.discovery.localNode:
      p.sendAddProvider(n, cId, pr)
    else:
      p.addProviderLocal(cId, pr)

## ---- GetProviders ----

const
  protoIdGetProviders = "GP".toBytes()

proc decode*(
  T: typedesc[GetProvidersMessage],
  buffer: openArray[byte]): Result[GetProvidersMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = GetProvidersMessage()

  ? pb.getRequiredField(1, msg.cId)

  ok(msg)

proc encode*(msg: GetProvidersMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.cId)

  pb.finish()
  pb.buffer

proc decode*(
  T: typedesc[ProvidersMessage],
  buffer: openArray[byte]): Result[ProvidersMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = ProvidersMessage()

  ? pb.getRequiredField(1, msg.total)
  discard ? pb.getRepeatedField(2, msg.provs)

  ok(msg)

proc encode*(msg: ProvidersMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.total)
  for prov in msg.provs:
    pb.write(2, prov)

  pb.finish()
  pb.buffer

proc sendGetProviders(p: ProvidersProtocol, dst: Node,
                       cId: NodeId): Future[ProvidersMessage]
                       {.async.} =
  let msg = GetProvidersMessage(cId: cId)
  trace "sendGetProviders", msg
  let respbytes = await p.discovery.talkReq(dst, protoIdGetProviders, msg.encode())
  if respbytes.isOK():
    let a = respbytes.get()
    result = ProvidersMessage.decode(a).get()
  else:
    trace "sendGetProviders", msg
    result = ProvidersMessage() #TODO: add error handling

proc getProvidersLocal*(
    p: ProvidersProtocol,
    cId: NodeId,
    maxitems: int = 5,
  ): seq[PeerRecord] {.raises: [KeyError,Defect].}=
  result = if (cId in p.providers): p.providers[cId] else: @[]

proc getProviders*(
    p: ProvidersProtocol,
    cId: NodeId,
    maxitems: int = 5,
    timeout: timer.Duration = chronos.milliseconds(5000)
  ): Future[seq[PeerRecord]] {.async.} =
  ## Search for providers of the given cId.

  # What providers do we know about?
  result = p.getProvidersLocal(cId, maxitems)
  trace "local providers:", result

  let nodesNearby = await p.discovery.lookup(cId)
  trace "nearby:", nodesNearby
  var providersFut: seq[Future[ProvidersMessage]]
  for n in nodesNearby:
    if n != p.discovery.localNode:
      providersFut.add(p.sendGetProviders(n, cId))

  while providersFut.len > 0:
    let providersMsg = await one(providersFut)
    # trace "Got providers response", providersMsg

    let index = providersFut.find(providersMsg)
    if index != -1:
      providersFut.del(index)

    let providersMsg2 = await providersMsg
    trace "2", providersMsg2

    let providers = providersMsg.read.provs
    result = result.concat(providers).deduplicate
    # TODO: hsndle timeout
    #
  trace "getProviders collected: ", result

proc recvGetProviders(p: ProvidersProtocol, nodeId: NodeId, payload: openArray[byte]) : ProvidersMessage
    {.raises: [Defect].} =
  trace "recvGetProviders"
  let msg = GetProvidersMessage.decode(payload).get()
  trace "<<< get_providers ",  src = nodeId, dst = p.discovery.localNode.id, cid = msg.cId
  #TODO: add checks, add signed version
  let provs = p.providers.getOrDefault(msg.cId)

  trace "providers:", provs
  ##TODO: handle multiple messages
  ProvidersMessage(total: 1, provs: provs)


proc registerGetProviders(p: ProvidersProtocol) =
  proc handler(protocol: TalkProtocol, request: seq[byte], fromId: NodeId, fromUdpAddress: Address): seq[byte]
    {.gcsafe, raises: [Defect].} =
    let returnMsg = recvGetProviders(p, fromId, request)
    trace "returnMsg", returnMsg
    returnMsg.encode() # TODO: response

  let protocol = TalkProtocol(protocolHandler: handler)
  discard p.discovery.registerTalkProtocol(protoIdGetProviders, protocol) #TODO: handle error

proc newProvidersProtocol*(d: protocol.Protocol) : ProvidersProtocol =
  result.new()
  result.discovery = d
  result.registerAddProvider()
  result.registerGetProviders()
