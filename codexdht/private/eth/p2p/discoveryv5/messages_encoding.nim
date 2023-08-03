# codex-dht - Codex DHT
# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## Discovery v5 packet encoding as specified at
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#packet-encoding

import
  std/net,
  chronicles,
  stew/endians2,
  libp2p/routing_record,
  libp2p/signed_envelope,
  "."/[messages, spr, node],
  ../../../../dht/providers_encoding

from stew/objects import checkedEnumAssign

type
  DecodeResult*[T] = Result[T, cstring]

  Distances = seq[uint16]

  EncodedMessage = seq[byte]

  IPv4 = array[0..3, uint8]

  IPv6 = array[0..15, uint8]

  Port = uint16

proc getField*(pb: ProtoBuffer, field: int,
               reqId: var RequestId): ProtoResult[bool] {.inline.} =
  ## Read ``RequestId`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  elif buffer.len > 8:
    ok(false) # RequestId must not be more than 8 bytes
  else:
    reqId = RequestId(id: buffer)
    ok(true)

proc write*(pb: var ProtoBuffer, field: int, reqId: RequestId) =
  ## Write RequestId value ``reqId`` to object ``pb`` using ProtoBuf's encoding.
  let encoded = reqId.id
  write(pb, field, encoded)

proc decode*(
  T: typedesc[PingMessage],
  buffer: openArray[byte]): Result[PingMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = PingMessage()

  ? pb.getRequiredField(1, msg.sprSeq)

  ok(msg)

proc encode*(msg: PingMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.sprSeq)

  pb.finish()
  pb.buffer

proc getField*(pb: ProtoBuffer, field: int,
               ipv4: var IPv4): ProtoResult[bool] {.inline.} =
  ## Read ``IPv4`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    for i in 0..<ipv4.len: ipv4[i] = buffer[i]
    ok(true)

proc getField*(pb: ProtoBuffer, field: int,
               ipv6: var IPv6): ProtoResult[bool] {.inline.} =
  ## Read ``IPv6`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    for i in 0..<ipv6.len: ipv6[i] = buffer[i]
    ok(true)

proc getField*(pb: ProtoBuffer, field: int,
               family: var IpAddressFamily): ProtoResult[bool] {.inline.} =
  ## Read ``IpAddressFamily`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    family = endians2.fromBytesBE(uint8, buffer).IpAddressFamily
    ok(true)

proc write*(pb: var ProtoBuffer, field: int, family: IpAddressFamily) =
  ## Write IpAddressFamily value ``family`` to object ``pb`` using ProtoBuf's encoding.
  let encoded = family.uint8.toBytesBe()
  write(pb, field, encoded)

proc decode*(
  T: typedesc[IpAddress],
  buffer: openArray[byte]): Result[IpAddress, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var family: IpAddressFamily

  ? pb.getRequiredField(1, family)

  var ip = IpAddress(family: family)

  case ip.family:
  of IpAddressFamily.IPv6:
    ? pb.getRequiredField(2, ip.address_v6)
  of IpAddressFamily.IPv4:
    ? pb.getRequiredField(2, ip.address_v4)

  ok(ip)

proc encode*(ip: IpAddress): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, ip.family)
  case ip.family:
  of IpAddressFamily.IPv6:
    pb.write(2, ip.address_v6)
  of IpAddressFamily.IPv4:
    pb.write(2, ip.address_v4)

  pb.finish()
  pb.buffer

proc getField*(pb: ProtoBuffer, field: int,
               ip: var IpAddress): ProtoResult[bool] {.inline.} =
  ## Read ``IpAddress`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    let res2 = IpAddress.decode(buffer)
    if res2.isOk():
      ip = res2.get()
      ok(true)
    else:
      err(ProtoError.IncorrectBlob)

proc write*(pb: var ProtoBuffer, field: int, ip: IpAddress) =
  ## Write IpAddress value ``ip`` to object ``pb`` using ProtoBuf's encoding.
  let encoded = ip.encode()
  write(pb, field, encoded)

proc getField*(pb: ProtoBuffer, field: int,
               port: var Port): ProtoResult[bool] {.inline.} =
  ## Read ``Port`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    port = uint16.fromBytesBE(buffer)
    ok(true)

proc write*(pb: var ProtoBuffer, field: int, port: Port) =
  ## Write Port value ``port`` to object ``pb`` using ProtoBuf's encoding.
  write(pb, field, port.toBytesBE())

proc decode*(
  T: typedesc[PongMessage],
  buffer: openArray[byte]): Result[PongMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = PongMessage()

  ? pb.getRequiredField(1, msg.sprSeq)
  ? pb.getRequiredField(2, msg.ip)
  ? pb.getRequiredField(3, msg.port)

  ok(msg)

proc encode*(msg: PongMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.sprSeq)
  pb.write(2, msg.ip)
  pb.write(3, msg.port)

  pb.finish()
  pb.buffer

proc getRepeatedField*(pb: ProtoBuffer, field: int,
                       distances: var Distances): ProtoResult[bool] {.inline.} =
  ## Read ``Distances`` from ProtoBuf's message and validate it
  var buffers: seq[seq[byte]]
  distances.setLen(0)
  let res = ? pb.getRepeatedField(field, buffers)
  if not(res):
    ok(false)
  else:
    for b in buffers:
      distances.add(uint16.fromBytesBE(b))
    ok(true)

proc decode*(
  T: typedesc[FindNodeMessage],
  buffer: openArray[byte]): Result[FindNodeMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = FindNodeMessage()

  ? pb.getRequiredRepeatedField(1, msg.distances)

  ok(msg)

proc encode*(msg: FindNodeMessage): seq[byte] =
  var pb = initProtoBuffer()

  for d in msg.distances:
    pb.write(1, d.toBytesBE())

  pb.finish()
  pb.buffer

proc decode*(
  T: typedesc[FindNodeFastMessage],
  buffer: openArray[byte]): Result[FindNodeFastMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = FindNodeFastMessage()

  ? pb.getRequiredField(1, msg.target)

  ok(msg)

proc encode*(msg: FindNodeFastMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.target)

  pb.finish()
  pb.buffer

proc decode*(
  T: typedesc[NodesMessage],
  buffer: openArray[byte]): Result[NodesMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = NodesMessage()

  ? pb.getRequiredField(1, msg.total)
  discard ? pb.getRepeatedField(2, msg.sprs)

  ok(msg)

proc encode*(msg: NodesMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.total)
  for r in msg.sprs:
    pb.write(2, r)

  pb.finish()
  pb.buffer

proc decode*(
  T: typedesc[TalkReqMessage],
  buffer: openArray[byte]): Result[TalkReqMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = TalkReqMessage()

  ? pb.getRequiredField(1, msg.protocol)
  ? pb.getRequiredField(2, msg.request)

  ok(msg)

proc encode*(msg: TalkReqMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.protocol)
  pb.write(2, msg.request)

  pb.finish()
  pb.buffer

proc decode*(
  T: typedesc[TalkRespMessage],
  buffer: openArray[byte]): Result[TalkRespMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = TalkRespMessage()

  ? pb.getRequiredField(2, msg.response)

  ok(msg)

proc encode*(msg: TalkRespMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(2, msg.response)

  pb.finish()
  pb.buffer

proc encodeMessage*[T: SomeMessage](p: T, reqId: RequestId): seq[byte] =
  result = newSeqOfCap[byte](64)
  result.add(messageKind(T).ord)

  let encoded =
    try: p.encode()
    except ResultError[CryptoError] as e:
      error "Failed to encode protobuf message", typ = $T, msg = e.msg
      @[]
  var pb = initProtoBuffer()
  pb.write(1, reqId)
  pb.write(2, encoded)
  pb.finish()
  result.add(pb.buffer)
  trace "Encoded protobuf message", typ = $T, encoded

proc decodeMessage*(body: openArray[byte]): DecodeResult[Message] =
  ## Decodes to the specific `Message` type.
  if body.len < 1:
    return err("No message data")

  var kind: MessageKind
  if not checkedEnumAssign(kind, body[0]):
    return err("Invalid message type")

  var message = Message(kind: kind)

  let pb = initProtoBuffer(body[1..body.high])

  var
    reqId: RequestId
    encoded: EncodedMessage

  if pb.getRequiredField(1, reqId).isErr:
    return err("Invalid request-id")

  message.reqId = reqId

  if pb.getRequiredField(2, encoded).isErr:
    return err("Invalid message encoding")

  case kind
  of unused: return err("Invalid message type")

  of ping:
    let res = PingMessage.decode(encoded)
    if res.isOk:
      message.ping = res.get
      return ok(message)
    else:
      return err("Unable to decode PingMessage")

  of pong:
    let res = PongMessage.decode(encoded)
    if res.isOk:
      message.pong = res.get
      return ok(message)
    else:
      return err("Unable to decode PongMessage")

  of findNode:
    let res = FindNodeMessage.decode(encoded)
    if res.isOk:
      message.findNode = res.get
      return ok(message)
    else:
      return err("Unable to decode FindNodeMessage")

  of nodes:
    let res = NodesMessage.decode(encoded)
    if res.isOk:
      message.nodes = res.get
      return ok(message)
    else:
      return err("Unable to decode NodesMessage")

  of talkReq:
    let res = TalkReqMessage.decode(encoded)
    if res.isOk:
      message.talkReq = res.get
      return ok(message)
    else:
      return err("Unable to decode TalkReqMessage")

  of talkResp:
    let res = TalkRespMessage.decode(encoded)
    if res.isOk:
      message.talkResp = res.get
      return ok(message)
    else:
      return err("Unable to decode TalkRespMessage")

  of findNodeFast:
    let res = FindNodeFastMessage.decode(encoded)
    if res.isOk:
      message.findNodeFast = res.get
      return ok(message)
    else:
      return err("Unable to decode FindNodeFastMessage")

  of addProvider:
    let res = AddProviderMessage.decode(encoded)
    if res.isOk:
      message.addProvider = res.get
      return ok(message)
    else:
      return err "Unable to decode AddProviderMessage"

  of getProviders:
    let res = GetProvidersMessage.decode(encoded)
    if res.isOk:
      message.getProviders = res.get
      return ok(message)
    else:
      return err("Unable to decode GetProvidersMessage")

  of providers:
    let res = ProvidersMessage.decode(encoded)
    if res.isOk:
      message.provs = res.get
      return ok(message)
    else:
      return err("Unable to decode ProvidersMessage")

  of regTopic, ticket, regConfirmation, topicQuery:
    # We just pass the empty type of this message without attempting to
    # decode, so that the protocol knows what was received.
    # But we ignore the message as per specification as "the content and
    # semantics of this message are not final".
    discard
