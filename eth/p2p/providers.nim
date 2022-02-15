# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronos,
  chronicles,
  std/tables,
  stew/byteutils, # toBytes
  discoveryv5/[protocol, node],
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
    total*: uint32
    enrs*: seq[PeerRecord]

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
  p.providers.mgetOrPut(cId, @[]).add(prov)

proc recvAddProvider(p: ProvidersProtocol, nodeId: NodeId, payload: openArray[byte])
    {.raises: [Defect].} =
  #TODO: add checks, add signed version
  let msg = AddProviderMessage.decode(payload).get()
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
  for n in result:
    if n != p.discovery.localNode:
      p.sendAddProvider(n, cId, pr)
    else:
      p.addProviderLocal(cId, pr)
