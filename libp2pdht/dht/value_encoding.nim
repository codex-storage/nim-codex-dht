import
  ../discv5/[node],
  libp2p/protobuf/minprotobuf,
  ./value_messages

func getField(pb: ProtoBuffer, field: int,
               nid: var NodeId): ProtoResult[bool] {.inline.} =
  ## Read ``NodeId`` from ProtoBuf's message and validate it
  var buffer: seq[byte]
  let res = ? pb.getField(field, buffer)
  if not(res):
    ok(false)
  else:
    nid = readUintBE[256](buffer)
    ok(true)

func write(pb: var ProtoBuffer, field: int, nid: NodeId) =
  ## Write NodeId value ``nodeid`` to object ``pb`` using ProtoBuf's encoding.
  write(pb, field, nid.toBytesBE())

proc decode*(
  T: typedesc[AddValueMessage],
  buffer: openArray[byte]): Result[AddValueMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = AddValueMessage()

  ? pb.getRequiredField(1, msg.cId)
  ? pb.getRequiredField(2, msg.value)

  ok(msg)

proc encode*(msg: AddValueMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.cId)
  pb.write(2, msg.value)

  pb.finish()
  pb.buffer

proc decode*(
  T: typedesc[GetValueMessage],
  buffer: openArray[byte]): Result[GetValueMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = GetValueMessage()

  ? pb.getRequiredField(1, msg.cId)

  ok(msg)

proc encode*(msg: GetValueMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.cId)

  pb.finish()
  pb.buffer

proc decode*(
  T: typedesc[ValueMessage],
  buffer: openArray[byte]): Result[ValueMessage, ProtoError] =

  let pb = initProtoBuffer(buffer)
  var msg = ValueMessage()
  ? pb.getRequiredField(1, msg.value)

  ok(msg)

proc encode*(msg: ValueMessage): seq[byte] =
  var pb = initProtoBuffer()

  pb.write(1, msg.value)

  pb.finish()
  pb.buffer
