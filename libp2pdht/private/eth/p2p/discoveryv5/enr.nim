# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
import
  chronicles,
  std/[options, sugar],
  pkg/stew/[results, byteutils],
  stew/endians2,
  stew/shims/net,
  stew/base64,
  eth/rlp,
  eth/keys,
  libp2p/crypto/crypto,
  libp2p/crypto/secp,
  libp2p/routing_record,
  libp2p/multicodec
from chronos import TransportAddress, initTAddress

export options, results

type
  Record* = object
    peerRecord: PeerRecord
    signedPeerRecord: Envelope

  EnrUri* = distinct string

  FieldPair* = (string, Field)
  ## dummy implementation

  Field = object
  ## dummy implementation

  RecordResult*[T] = Result[T, cstring]

proc seqNum*(r: Record): uint64 = 
    r.peerRecord.seqNo

#proc encode
proc append*(rlpWriter: var RlpWriter, value: Record) =
  # echo "encoding to:" & $value.signedPeerRecord.encode.get
  rlpWriter.append(value.signedPeerRecord.encode.get)

#proc decode
# some(rlp.decode(authdata.toOpenArray(recordPos, authdata.high),enr.Record))
# template decode*(bytes: openArray[byte], T: type): untyped =
#   mixin read
#   var rlp = rlpFromBytes(bytes)
#   rlp.read(T)
# proc read*(rlp: var Rlp, T: typedesc[Record]):
#     T {.raises: [RlpError, ValueError, Defect].} =
#   if not rlp.hasData() or not result.fromBytes(rlp.rawData):
#     # TODO: This could also just be an invalid signature, would be cleaner to
#     # split of RLP deserialisation errors from this.
#     raise newException(ValueError, "Could not deserialize")
#   rlp.skipElem()
# proc fromBytes*(r: var Record, s: openArray[byte]): bool =
  ## Loads ENR from rlp-encoded bytes, and validates the signature.

proc fromBytes(r: var Record, s: openArray[byte]): bool =
    # echo "decoding from:" & $s & $s.len
    let
        #TODO: thos is double work, 
        EnvelopeDomain = $multiCodec("libp2p-peer-record") # envelope domain as per RFC0002
        envelope = Envelope.decode(@s[2..^1], EnvelopeDomain) #TODO: this is just to remove RLP header. Ugly!
    if envelope.isErr:
        #echo "invalid ENV " & $envelope.error
        return false

    let 
        spr = PeerRecord.decode(envelope.get.payload).mapErr(x => EnvelopeInvalidProtobuf)
    if spr.isErr:
        #echo "invalid SPR " & $spr.error
        return false

    r.peerRecord = spr.get
    r.signedPeerRecord = envelope.get
    return true

proc read*(rlp: var Rlp, T: typedesc[Record]):
    T {.raises: [RlpError, ValueError, Defect].} =
    # echo "read:" & $rlp.rawData
    ## code directly borrowed from enr.nim
    if not rlp.hasData() or not result.fromBytes(rlp.rawData):
        # TODO: This could also just be an invalid signature, would be cleaner to
        # split of RLP deserialisation errors from this.
        raise newException(ValueError, "Could not deserialize")
    rlp.skipElem()

proc get*(r: Record, T: type crypto.PublicKey): Option[T] =
  ## Get the `PublicKey` from provided `Record`. Return `none` when there is
  ## no `PublicKey` in the record.
  some(r.signedPeerRecord.publicKey)

func pkToPk(pk: crypto.PublicKey) : Option[keys.PublicKey] =
  some((keys.PublicKey)(pk.skkey))

func pkToPk(pk: keys.PublicKey) : Option[crypto.PublicKey] =
  some(crypto.PublicKey.init((secp.SkPublicKey)(pk)))

func pkToPk(pk: crypto.PrivateKey) : Option[keys.PrivateKey] =
  some((keys.PrivateKey)(pk.skkey))

func pkToPk(pk: keys.PrivateKey) : Option[crypto.PrivateKey] =
  some(crypto.PrivateKey.init((secp.SkPrivateKey)(pk)))

proc get*(r: Record, T: type keys.PublicKey): Option[T] =
  ## Get the `PublicKey` from provided `Record`. Return `none` when there is
  ## no `PublicKey` in the record.
  ## PublicKey* = distinct SkPublicKey
  let
    pk = r.signedPeerRecord.publicKey
  pkToPk(pk)

proc update*(r: var Record, pk: crypto.PrivateKey,
                            ip: Option[ValidIpAddress],
                            tcpPort, udpPort: Option[Port] = none[Port](),
                            extraFields: openArray[FieldPair] = []):
                            RecordResult[void] =
  ## Update a `Record` with given ip address, tcp port, udp port and optional
  ## custom k:v pairs.
  ##
  ## In case any of the k:v pairs is updated or added (new), the sequence number
  ## of the `Record` will be incremented and a new signature will be applied.
  ##
  ## Can fail in case of wrong `PrivateKey`, if the size of the resulting record
  ## exceeds `maxEnrSize` or if maximum sequence number is reached. The `Record`
  ## will not be altered in these cases.
  r.signedPeerRecord = Envelope.init(pk, r.peerRecord).get
  #TODO: handle fields

proc update*(r: var Record, pk: keys.PrivateKey,
                            ip: Option[ValidIpAddress],
                            tcpPort, udpPort: Option[Port] = none[Port](),
                            extraFields: openArray[FieldPair] = []):
                            RecordResult[void] =
  let cPk = pkToPk(pk).get
  r.update(cPk, ip, tcpPort, udpPort, extraFields)

proc toTypedRecord*(r: Record) : RecordResult[Record] = ok(r)

proc ip*(r: Record): Option[array[4, byte]] =
    let ma = r.peerRecord.addresses[0].address

    let code = ma[0].get.protoCode()
    if code.isOk and code.get == multiCodec("ip4"):
      var ipbuf: array[4, byte]
      let res = ma[0].get.protoArgument(ipbuf)
      if res.isOk:
        return some(ipbuf)

#         err("Incorrect IPv4 address")
#       else:
#         if (?(?ma[1]).protoArgument(pbuf)) == 0:
#           err("Incorrect port number")
#         else:
#           res.port = Port(fromBytesBE(uint16, pbuf))
#           ok(res)
#     else:

#   else:
#     err("MultiAddress must be wire address (tcp, udp or unix)")

proc udp*(r: Record): Option[int] =
    let ma = r.peerRecord.addresses[0].address

    let code = ma[1].get.protoCode()
    if code.isOk and code.get == multiCodec("udp"):
      var pbuf: array[2, byte]
      let res = ma[1].get.protoArgument(pbuf)
      if res.isOk:
        let p = fromBytesBE(uint16, pbuf)  
        return some(p.int)

proc fromURI*(r: var Record, s: string): bool =
  ## Loads Record from its text encoding. Validates the signature.
  ## TODO
  #error "fromURI not implemented"
  false
#   const prefix = "enr:"
#   if s.startsWith(prefix):
#     result = r.fromBase64(s[prefix.len .. ^1])

template fromURI*(r: var Record, url: EnrUri): bool =
  fromURI(r, string(url))

proc toBase64*(r: Record): string =
  result = Base64Url.encode(r.signedPeerRecord.encode.get)

proc toURI*(r: Record): string = "spr:" & r.toBase64

proc init*(T: type Record, seqNum: uint64,
                           pk: crypto.PrivateKey,
                           ip: Option[ValidIpAddress],
                           tcpPort, udpPort: Option[Port],
                           extraFields: openArray[FieldPair] = []):
                           RecordResult[T] =
  ## Initialize a `Record` with given sequence number, private key, optional
  ## ip address, tcp port, udp port, and optional custom k:v pairs.
  ##
  ## Can fail in case the record exceeds the `maxEnrSize`.
  
  let peerId = PeerId.init(pk).get
  var ma:MultiAddress
  if ip.isSome and udpPort.isSome:
    # let ta = initTAddress(ip.get, udpPort.get)
    # echo ta
    # ma = MultiAddress.init(ta).get
    #let ma1 = MultiAddress.init("/ip4/127.0.0.1").get() #TODO
    #let ma2 = MultiAddress.init(multiCodec("udp"), udpPort.get.int).get
    #ma = ma1 & ma2
    ma = MultiAddress.init("/ip4/127.0.0.1/udp/" & $udpPort.get.int).get #TODO
  else:
    ma = MultiAddress.init()
    # echo "not implemented"

  var res: Record
  res.peerRecord = PeerRecord.init(peerId, seqNum, @[ma])
  res.signedPeerRecord = Envelope.init(pk, res.peerRecord).get
  ok(res)

proc init*(T: type Record, seqNum: uint64,
                           pk: keys.PrivateKey,
                           ip: Option[ValidIpAddress],
                           tcpPort, udpPort: Option[Port],
                           extraFields: openArray[FieldPair] = []):
                           RecordResult[T] =
  let kPk = pkToPk(pk).get
  Record.init(seqNum, kPk, ip, tcpPort, udpPort, extraFields)

proc contains*(r: Record, fp: (string, seq[byte])): bool =
  # TODO: use FieldPair for this, but that is a bit cumbersome. Perhaps the
  # `get` call can be improved to make this easier.
  # TODO: implement
  #error "not implemented"
  return false

template toFieldPair*(key: string, value: auto): FieldPair =
  #error "not implemented"
  (key, Field())

proc update*(record: var Record, pk: keys.PrivateKey,
    fieldPairs: openArray[FieldPair]): RecordResult[void] =
  #error "not implemented"
  err("not implemented")

proc `==`*(a, b: Record): bool = a.signedPeerRecord == b.signedPeerRecord
