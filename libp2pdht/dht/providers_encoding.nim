import
  ../discv5/[node],
  libp2p/[routing_record, signed_envelope],
  libp2p/protobuf/minprotobuf,
  ./providers_messages

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

func write*[T: SignedPeerRecord | PeerRecord | Envelope](
    pb: var ProtoBuffer,
    field: int,
    env: T) {.raises: [Defect, ResultError[CryptoError]].} =

  ## Write Envelope value ``env`` to object ``pb`` using ProtoBuf's encoding.
  let encoded = env.encode().tryGet()
  write(pb, field, encoded)

proc getRepeatedField*(pb: ProtoBuffer, field: int,
                       value: var seq[SignedPeerRecord]): ProtoResult[bool] {.
     inline.} =
  var items: seq[seq[byte]]
  value.setLen(0)
  let res = ? pb.getRepeatedField(field, items)
  if not(res):
    ok(false)
  else:
    for item in items:
      let ma = SignedPeerRecord.decode(item)
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

