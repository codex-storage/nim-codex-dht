# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
import
  chronicles,
  std/[options, strutils, sugar],
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

export routing_record

from chronos import TransportAddress, initTAddress

export options, results

type
  SprUri* = distinct string

  RecordResult*[T] = Result[T, cstring]

proc seqNum*(r: SignedPeerRecord): uint64 =
    r.data.seqNo

#proc encode
proc append*(rlpWriter: var RlpWriter, value: SignedPeerRecord) =
  # echo "encoding to:" & $value.signedPeerRecord.encode.get
  var encoded = value.encode
  trace "Encoding SignedPeerRecord for RLP", bytes = encoded.get(@[])
  if encoded.isErr:
    error "Error encoding SignedPeerRecord for RLP", error = encoded.error
  rlpWriter.append encoded.get(@[])

proc fromBytes(r: var SignedPeerRecord, s: openArray[byte]): bool =
  trace "Decoding SignedPeerRecord for RLP", bytes = s

  let decoded = SignedPeerRecord.decode(@s)
  if decoded.isErr:
    error "Error decoding SignedPeerRecord", error = decoded.error
    return false

  r = decoded.get
  return true

proc read*(rlp: var Rlp, T: typedesc[SignedPeerRecord]):
    T {.raises: [RlpError, ValueError, Defect].} =
    # echo "read:" & $rlp.rawData
    ## code directly borrowed from spr.nim
    trace "Reading RLP SignedPeerRecord", rawData = rlp.rawData, toBytes = rlp.toBytes
    if not rlp.hasData() or not result.fromBytes(rlp.toBytes):
        # TODO: This could also just be an invalid signature, would be cleaner to
        # split of RLP deserialisation errors from this.
        raise newException(ValueError, "Could not deserialize")
    rlp.skipElem()

proc get*(r: SignedPeerRecord, T: type crypto.PublicKey): Option[T] =
  ## Get the `PublicKey` from provided `Record`. Return `none` when there is
  ## no `PublicKey` in the record.
  some(r.envelope.publicKey)

func pkToPk(pk: crypto.PublicKey) : Option[keys.PublicKey] =
  some((keys.PublicKey)(pk.skkey))

func pkToPk(pk: keys.PublicKey) : Option[crypto.PublicKey] =
  some(crypto.PublicKey.init((secp.SkPublicKey)(pk)))

func pkToPk(pk: crypto.PrivateKey) : Option[keys.PrivateKey] =
  some((keys.PrivateKey)(pk.skkey))

func pkToPk(pk: keys.PrivateKey) : Option[crypto.PrivateKey] =
  some(crypto.PrivateKey.init((secp.SkPrivateKey)(pk)))

proc get*(r: SignedPeerRecord, T: type keys.PublicKey): Option[T] =
  ## Get the `PublicKey` from provided `Record`. Return `none` when there is
  ## no `PublicKey` in the record.
  ## PublicKey* = distinct SkPublicKey
  let
    pk = r.envelope.publicKey
  pkToPk(pk)

proc incSeqNo*(
    r: var SignedPeerRecord,
    pk: keys.PrivateKey): RecordResult[void] =

  let cryptoPk = pk.pkToPk.get() # TODO: remove when eth/keys removed

  r.data.seqNo.inc()
  r = ? SignedPeerRecord.init(cryptoPk, r.data).mapErr(
        (e: CryptoError) =>
          ("Error initialising SignedPeerRecord with incremented seqNo: " &
          $e).cstring
      )
  ok()


proc update*(r: var SignedPeerRecord, pk: crypto.PrivateKey,
                            ip: Option[ValidIpAddress],
                            tcpPort, udpPort: Option[Port] = none[Port]()):
                            RecordResult[void] =
  ## Update a `SignedPeerRecord` with given ip address, tcp port, udp port and optional
  ## custom k:v pairs.
  ##
  ## In case any of the k:v pairs is updated or added (new), the sequence number
  ## of the `Record` will be incremented and a new signature will be applied.
  ##
  ## Can fail in case of wrong `PrivateKey`, if the size of the resulting record
  ## exceeds `maxSprSize` or if maximum sequence number is reached. The `Record`
  ## will not be altered in these cases.

  # TODO: handle custom field pairs?
  # TODO: We have a mapping issue here because PeerRecord has multiple
  # addresses and the proc signature only allows updating of a single
  # ip/tcpPort/udpPort/extraFields

  let
    pubkey = r.get(crypto.PublicKey)
    keysPubKey = pubkey.get.pkToPk.get # remove when move away from eth/keys
    keysPrivKey = pk.pkToPk.get
  if pubkey.isNone() or keysPubKey != keysPrivKey.toPublicKey:
    return err("Public key does not correspond with given private key")

  let updated = if r.data.addresses.len == 0:
                  MultiAddress.init()
                else: r.data.addresses[0].address
  # TODO: Update MultiAddress details here
  if true: # only if we actually updated the SignedPeerRecord
    ? r.incSeqNo(keysPrivKey)
  r = ? SignedPeerRecord.init(pk, r.data)
          .mapErr((e: CryptoError) => ("Failed to update SignedPeerRecord: " & $e).cstring)

  return ok()

proc update*(r: var SignedPeerRecord, pk: keys.PrivateKey,
                            ip: Option[ValidIpAddress],
                            tcpPort, udpPort: Option[Port] = none[Port]()):
                            RecordResult[void] =
  let cPk = pkToPk(pk).get
  r.update(cPk, ip, tcpPort, udpPort)

proc toTypedRecord*(r: SignedPeerRecord) : RecordResult[SignedPeerRecord] = ok(r)

proc ip*(r: SignedPeerRecord): Option[array[4, byte]] =
    let ma = r.data.addresses[0].address

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

proc udp*(r: SignedPeerRecord): Option[int] =
    let ma = r.data.addresses[0].address

    let code = ma[1].get.protoCode()
    if code.isOk and code.get == multiCodec("udp"):
      var pbuf: array[2, byte]
      let res = ma[1].get.protoArgument(pbuf)
      if res.isOk:
        let p = fromBytesBE(uint16, pbuf)
        return some(p.int)

proc fromBase64*(r: var SignedPeerRecord, s: string): bool =
  ## Loads SPR from base64-encoded rlp-encoded bytes, and validates the
  ## signature.
  let bytes = Base64Url.decode(s)
  r.fromBytes(bytes)

proc fromURI*(r: var SignedPeerRecord, s: string): bool =
  ## Loads SignedPeerRecord from its text encoding. Validates the signature.
  ## TODO
  const prefix = "spr:"
  if s.startsWith(prefix):
    result = r.fromBase64(s[prefix.len .. ^1])

template fromURI*(r: var SignedPeerRecord, url: SprUri): bool =
  fromURI(r, string(url))

proc toBase64*(r: SignedPeerRecord): string =
  let encoded = r.encode
  if encoded.isErr:
    error "Failed to encode SignedPeerRecord", error = encoded.error
  result = Base64Url.encode(encoded.get(@[]))

proc toURI*(r: SignedPeerRecord): string = "spr:" & r.toBase64

proc init*(T: type SignedPeerRecord, seqNum: uint64,
                           pk: crypto.PrivateKey,
                           ip: Option[ValidIpAddress],
                           tcpPort, udpPort: Option[Port]):
                           RecordResult[T] =
  ## Initialize a `SignedPeerRecord` with given sequence number, private key, optional
  ## ip address, tcp port, udp port, and optional custom k:v pairs.
  ##
  ## Can fail in case the record exceeds the `maxSprSize`.

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

  let pr = PeerRecord.init(peerId, @[ma], seqNum)
  SignedPeerRecord.init(pk, pr).mapErr((e: CryptoError) => ("Failed to init SignedPeerRecord: " & $e).cstring)

proc init*(T: type SignedPeerRecord, seqNum: uint64,
                           pk: keys.PrivateKey,
                           ip: Option[ValidIpAddress],
                           tcpPort, udpPort: Option[Port]):
                           RecordResult[T] =
  let kPk = pkToPk(pk).get
  SignedPeerRecord.init(seqNum, kPk, ip, tcpPort, udpPort)

proc contains*(r: SignedPeerRecord, fp: (string, seq[byte])): bool =
  # TODO: use FieldPair for this, but that is a bit cumbersome. Perhaps the
  # `get` call can be improved to make this easier.
  # let field = r.tryGet(fp[0], seq[byte])
  # if field.isSome():
  #   if field.get() == fp[1]:
  #     return true
  # TODO: Implement if SignedPeerRecord custom field pairs are implemented
  return false

proc `==`*(a, b: SignedPeerRecord): bool = a.data == b.data
