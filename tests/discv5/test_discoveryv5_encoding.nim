{.used.}

import
  std/[options, sequtils, tables],
  chronicles, # delete me
  chronos,
  asynctest/unittest2,
  stint, stew/byteutils, stew/shims/net,
  eth/[keys,rlp],
  libp2pdht/discv5/[messages, messages_encoding, encoding, spr, node, sessions, protocol], # delete protocol
  ../dht/test_helper

suite "Discovery v5.1 Protocol Message Encodings":
  test "Ping Request":
    let
      sprSeq = 1'u64
      p = PingMessage(sprSeq: sprSeq)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(p, reqId)
    check byteutils.toHex(encoded) == "01c401820801"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == MessageKind.ping
      message.ping.sprSeq == sprSeq

  test "Pong Response":
    let
      sprSeq = 1'u64
      ip = IpAddress(family: IpAddressFamily.IPv4, address_v4: [127.byte, 0, 0, 1])
      port = 5000'u16
      p = PongMessage(sprSeq: sprSeq, ip: ip, port: port)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(p, reqId)
    check byteutils.toHex(encoded) == "02ca0101847f000001821388"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == pong
      message.pong.sprSeq == sprSeq
      message.pong.ip == ip
      message.pong.port == port

  test "FindNode Request":
    let
      distances = @[0x0100'u16]
      fn = FindNodeMessage(distances: distances)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(fn, reqId)
    check byteutils.toHex(encoded) == "03c501c3820100"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == MessageKind.findNode
      message.findNode.distances == distances

  test "Nodes Response (empty)":
    let
      total = 0x1'u32
      n = NodesMessage(total: total)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(n, reqId)
    check byteutils.toHex(encoded) == "04c30101c0"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == nodes
      message.nodes.total == total
      message.nodes.sprs.len() == 0

  test "Nodes Response (multiple)":
    var s1, s2: SignedPeerRecord
    check s1.fromURI("spr:CiQIARIgWu2YZ5TQVW1gWEfvQijVHqSBtjCbwDt9VppJvYpHX9wSAgMBGlUKJgAkCAESIFrtmGeU0FVtYFhH70Io1R6kgbYwm8A7fVaaSb2KR1_cEKz1xZEGGgsKCQQAAAAAkQIAARoLCgkEAAAAAJECAAIaCwoJBAAAAACRAgADKkAjkK9DeWc82uzd1AEjRr-ksQyRiQ7vYGV4Af3FAEi0JgHvMC8RCQdqn2wBYxvBcyO8o1XMEEKCG01AUZrJlCkD")
    check s2.fromURI("spr:CiQIARIguW3cNKnlvRsJVmV0ddgFMmvfAQLi0zf4tlt_6WGA03YSAgMBGlUKJgAkCAESILlt3DSp5b0bCVZldHXYBTJr3wEC4tM3-LZbf-lhgNN2EKz1xZEGGgsKCQQAAAAAkQIAARoLCgkEAAAAAJECAAIaCwoJBAAAAACRAgADKkC4Y9NkDHf-71LOvZon0NjmyzQnkm4IlAJGMDPS0cbSgIF3-2cECC5mRiXHjcHWlI5hPpxUURxFyIgSp7XX1jIL")
    let
      total = 0x1'u32
      n = NodesMessage(total: total, sprs: @[s1, s2])
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(n, reqId)
    check byteutils.toHex(encoded) == "04f9018f0101f9018ab8c30a24080112205aed986794d0556d605847ef4228d51ea481b6309bc03b7d569a49bd8a475fdc120203011a550a260024080112205aed986794d0556d605847ef4228d51ea481b6309bc03b7d569a49bd8a475fdc10acf5c591061a0b0a090400000000910200011a0b0a090400000000910200021a0b0a090400000000910200032a402390af4379673cdaecddd4012346bfa4b10c91890eef60657801fdc50048b42601ef302f1109076a9f6c01631bc17323bca355cc1042821b4d40519ac9942903b8c30a2408011220b96ddc34a9e5bd1b0956657475d805326bdf0102e2d337f8b65b7fe96180d376120203011a550a26002408011220b96ddc34a9e5bd1b0956657475d805326bdf0102e2d337f8b65b7fe96180d37610acf5c591061a0b0a090400000000910200011a0b0a090400000000910200021a0b0a090400000000910200032a40b863d3640c77feef52cebd9a27d0d8e6cb3427926e089402463033d2d1c6d2808177fb6704082e664625c78dc1d6948e613e9c54511c45c88812a7b5d7d6320b"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == nodes
      message.nodes.total == total
      message.nodes.sprs.len() == 2
      message.nodes.sprs[0] == s1
      message.nodes.sprs[1] == s2

  test "Talk Request":
    let
      tr = TalkReqMessage(protocol: "echo".toBytes(), request: "hi".toBytes())
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(tr, reqId)
    check byteutils.toHex(encoded) == "05c901846563686f826869"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == MessageKind.talkReq
      message.talkReq.protocol == "echo".toBytes()
      message.talkReq.request == "hi".toBytes()

  test "Talk Response":
    let
      tr = TalkRespMessage(response: "hi".toBytes())
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(tr, reqId)
    check byteutils.toHex(encoded) == "06c401826869"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == talkResp
      message.talkResp.response == "hi".toBytes()

  test "Ping with too large RequestId":
    let
      sprSeq = 1'u64
      p = PingMessage(sprSeq: sprSeq)
      # 1 byte too large
      reqId = RequestId(id: @[0.byte, 1, 2, 3, 4, 5, 6, 7, 8])
    let encoded = encodeMessage(p, reqId)
    check byteutils.toHex(encoded) == "01cd89000102030405060708820801"

    let decoded = decodeMessage(encoded)
    check decoded.isErr()

  test "Pong with invalid IP address size":
    # pong message with ip field of 5 bytes
    let encodedPong = "02cb0101857f00000102821388"

    let decoded = decodeMessage(hexToSeqByte(encodedPong))
    check decoded.isErr()

# According to test vectors:
# https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md#cryptographic-primitives
suite "Discovery v5.1 Cryptographic Primitives Test Vectors":
  test "ECDH":
    const
      # input
      publicKey = "0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
      secretKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      # expected output
      sharedSecret = "0x033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"

    let
      pub = keys.PublicKey.fromHex(publicKey)[]
      priv = keys.PrivateKey.fromHex(secretKey)[]
      eph = ecdhRawFull(priv, pub)
    check:
      eph.data == hexToSeqByte(sharedSecret)

  test "Key Derivation":
    const
      # input
      ephemeralKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      destPubkey = "0x0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
      nodeIdA = "0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
      nodeIdB = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
      challengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      # expected output
      initiatorKey = "0xdccc82d81bd610f4f76d3ebe97a40571"
      recipientKey = "0xac74bb8773749920b0d3a8881c173ec5"

    let secrets = deriveKeys(
      NodeId.fromHex(nodeIdA),
      NodeId.fromHex(nodeIdB),
      keys.PrivateKey.fromHex(ephemeralKey)[],
      keys.PublicKey.fromHex(destPubkey)[],
      hexToSeqByte(challengeData))

    check:
      secrets.initiatorKey == hexToByteArray[aesKeySize](initiatorKey)
      secrets.recipientKey == hexToByteArray[aesKeySize](recipientKey)

  test "Nonce Signing":
    const
      # input
      staticKey = "0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
      challengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      ephemeralPubkey = "0x039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
      nodeIdB = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"
      # expected output
      idSignature = "0x94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6"

    let
      privKey = keys.PrivateKey.fromHex(staticKey)[]
      signature = createIdSignature(
        privKey,
        hexToSeqByte(challengeData),
        hexToSeqByte(ephemeralPubkey),
        NodeId.fromHex(nodeIdB))
    check:
      signature.toRaw() == hexToByteArray[64](idSignature)
      verifyIdSignature(signature, hexToSeqByte(challengeData),
        hexToSeqByte(ephemeralPubkey), NodeId.fromHex(nodeIdB),
        privKey.toPublicKey())

  test "Encryption/Decryption":
    const
      # input
      encryptionKey = "0x9f2d77db7004bf8a1a85107ac686990b"
      nonce = "0x27b5af763c446acd2749fe8e"
      pt = "0x01c20101"
      ad = "0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903"
      # expected output
      messageCiphertext = "0xa5d12a2d94b8ccb3ba55558229867dc13bfa3648"

    let encrypted = encryptGCM(hexToByteArray[aesKeySize](encryptionKey),
                               hexToByteArray[gcmNonceSize](nonce),
                               hexToSeqByte(pt),
                               hexToByteArray[32](ad))
    check encrypted == hexToSeqByte(messageCiphertext)

# According to test vectors:
# https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md#packet-encodings
suite "Discovery v5.1 Packet Encodings Test Vectors":
  const
    nodeAKey = "0xfe5f08c842aa946659b266ce68faa5d2fd982634594dccdf7f916e3fcf0541a3"
    nodeBKey = "0x00064765abe9a4e63b068b5af99c26c61c8ade9bfdae6494873b137ec8152578"

  var
    codecA, codecB: Codec
    nodeA, nodeB: Node
    privKeyA, privKeyB: keys.PrivateKey

  setup:
    privKeyA = keys.PrivateKey.fromHex(nodeAKey)[] # sender -> encode
    privKeyB = keys.PrivateKey.fromHex(nodeBKey)[] # receive -> decode

    let
      enrRecA = SignedPeerRecord.init(1, privKeyA,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")

      enrRecB = SignedPeerRecord.init(1, privKeyB,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")

    nodeA = newNode(enrRecA).expect("Properly initialized record")
    nodeB = newNode(enrRecB).expect("Properly initialized record")
    codecA = Codec(localNode: nodeA, privKey: privKeyA,
      sessions: Sessions.init(5))
    codecB = Codec(localNode: nodeB, privKey: privKeyB,
      sessions: Sessions.init(5))

  test "Ping Ordinary Message Packet":
    const
      readKey = "0x00000000000000000000000000000000"
      pingReqId = "0x00000001"
      pingSprSeq = 2'u64

      encodedPacket =
        "00000000000000000000000000000000ff023f48428a4b169957779cb1d56ac3" &
        "bc8023b3e9d565dbfa9a6ff526a2a1bc89cdf2d341e6fb3d7b6207e512443bc7" &
        "99cd8a4d203201dde36d1a6d388297fa011578c000e37469965a293abffc4058" &
        "9b"

    let dummyKey = "0x00000000000000000000000000000001" # of no importance
    codecA.sessions.store(nodeB.id, nodeB.address.get(),
      hexToByteArray[aesKeySize](dummyKey), hexToByteArray[aesKeySize](readKey))
    codecB.sessions.store(nodeA.id, nodeA.address.get(),
      hexToByteArray[aesKeySize](readKey), hexToByteArray[aesKeySize](dummyKey))

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))
    check:
      decoded.isOk()
      decoded.get().messageOpt.isSome()
      decoded.get().messageOpt.get().reqId.id == hexToSeqByte(pingReqId)
      decoded.get().messageOpt.get().kind == MessageKind.ping
      decoded.get().messageOpt.get().ping.sprSeq == pingSprSeq

  test "Whoareyou Packet":
    const
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouSprSeq = 0

      encodedPacket =
        "00000000000000000000000000000000ff023f48428a4b169857779cb1d56ac3" &
        "bc8023b3e9d55d96c6f8f156eaae08ccd97a4fed2441cf6bb65b940facfcff"

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().flag == Flag.Whoareyou
      decoded.get().whoareyou.requestNonce == hexToByteArray[gcmNonceSize](whoareyouRequestNonce)
      decoded.get().whoareyou.idNonce == hexToByteArray[idNonceSize](whoareyouIdNonce)
      decoded.get().whoareyou.recordSeq == whoareyouSprSeq
      decoded.get().whoareyou.challengeData == hexToSeqByte(whoareyouChallengeData)

      codecB.decodePacket(nodeA.address.get(),
        hexToSeqByte(encodedPacket & "00")).isErr()

  test "Ping Handshake Message Packet":
    const
      pingReqId = "0x00000001"
      pingSprSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouSprSeq = 1'u64

      encodedPacket =
        "00000000000000000000000000000000ff023f48428a4b169b57779cb1d56ac3" &
        "bc8023b3e9d5c6dbfa9a6ff526a2a1bc89cdf2d341e6fb3d7b6207e512443bc7" &
        "99cd8a4d20320147b277d497aac4ff05f71dd7e65689d09f0efa7b8431022111" &
        "07db3022756934ae242b67321aa2eac04c6522a397253dce85d1c276c1502a91" &
        "a4d36dcce3064067e81dfd3a9a55afc76ca30a7e3fbd5657e1e271b4275a76cf" &
        "517a562b5f143b416a609d4d7541044533b877a2ded6785f40f5086a97dec233" &
        "b025e4d5"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouSprSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = some(privKeyA.toPublicKey())
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == MessageKind.ping
      decoded.get().message.ping.sprSeq == pingSprSeq
      decoded.get().node.isNone()

      codecB.decodePacket(nodeA.address.get(),
        hexToSeqByte(encodedPacket & "00")).isErr()

  test "Ping Handshake Message Packet with SPR":
    const
      pingReqId = "0x00000001"
      pingSprSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouSprSeq = 0'u64

      encodedPacket =
        "00000000000000000000000000000000ff023f48428a4b169b57779cb1d56ac3" &
        "bc8023b3e9d474dbfa9a6ff526a2a1bc89cdf2d341e6fb3d7b6207e512443bc7" &
        "99cd8a4d20320147b2b0fbec3854e9ab1608f6b13bc38a03f7506ea8a33e94ae" &
        "ce56d7c2428d96116d338e685b66e340cc0e4ecfb8bfddd34c8e747fd887b86a" &
        "6a26a5a77f76896a971d46a883e9ff7c7750ec3c01eb931cc12c706162c29ced" &
        "85be0126dcd9b23e38aeb6681d755368e815d0fa6d0409a31b938e7bccbb9e99" &
        "a0c91c92c02b78b5ea7f8cbeb4968e68d655b358f4ba15e4ad4a9f6704497c6f" &
        "c46f9f5b9626a130d25ac7e250abbbacf8cdffc7b53957550f6e1736fec386aa" &
        "eb305dcdadbe57f87ebd7ce21e9da3679964b8a978b7d29ea4727a1f680758d5" &
        "8ff4eaaef74625630bd50fedbcde23f505c3c11a1ac8a9bb6e2d06c1628cce59" &
        "c0d90edad109285be25ef9491b3beaf04761bfb476e70be5330f157c6975bdab" &
        "9e48fba9eb5732f51a364de43d7d32cf1682"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouSprSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = none(keys.PublicKey)
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == MessageKind.ping
      decoded.get().message.ping.sprSeq == pingSprSeq
      decoded.get().node.isSome()

      codecB.decodePacket(nodeA.address.get(),
        hexToSeqByte(encodedPacket & "00")).isErr()

# TODO: Delete this entire suite once Protobufs are completely incorporated
suite "NEW ENCODING OUTPUT ONLY - REMOVE AFTER PROTOBUFS COMPLETE, Discovery v5.1 Packet Encodings Test Vectors":
  var
    rng = keys.newRng()
    nodeAKey = "0xfe5f08c842aa946659b266ce68faa5d2fd982634594dccdf7f916e3fcf0541a3"
    nodeBKey = "0x00064765abe9a4e63b068b5af99c26c61c8ade9bfdae6494873b137ec8152578"

  var
    codecA, codecB: Codec
    nodeA, nodeB: Node
    privKeyA, privKeyB: keys.PrivateKey

  setup:
    privKeyA = keys.PrivateKey.fromHex(nodeAKey)[] # sender -> encode
    privKeyB = keys.PrivateKey.fromHex(nodeBKey)[] # receive -> decode

    let
      enrRecA = SignedPeerRecord.init(1, privKeyA,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")

      enrRecB = SignedPeerRecord.init(1, privKeyB,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")

    nodeA = newNode(enrRecA).expect("Properly initialized record")
    nodeB = newNode(enrRecB).expect("Properly initialized record")
    codecA = Codec(localNode: nodeA, privKey: privKeyA,
      sessions: Sessions.init(5))
    codecB = Codec(localNode: nodeB, privKey: privKeyB,
      sessions: Sessions.init(5))

  test "Ping Ordinary Message Packet":
    const
      readKey = "0x00000000000000000000000000000000"
      pingReqId = "0x00000001"
      pingSprSeq = 2'u64

    let dummyKey = "0x00000000000000000000000000000001" # of no importance
    codecA.sessions.store(nodeB.id, nodeB.address.get(),
      hexToByteArray[aesKeySize](dummyKey), hexToByteArray[aesKeySize](readKey))
    codecB.sessions.store(nodeA.id, nodeA.address.get(),
      hexToByteArray[aesKeySize](readKey), hexToByteArray[aesKeySize](dummyKey))

    # TODO: Remove me once all protobufs in place
    let
      ping = PingMessage(sprSeq: pingSprSeq)
      reqId = RequestId(id: hexToSeqByte(pingReqId))
      message = encodeMessage(ping, reqId)

    var nonce: AESGCMNonce
    let
      nonceHex = "0x0102030405060708090a0b0c0d0e0f10"
      nonceBytes = nonceHex.hexToByteArray(gcmNonceSize)
    copyMem(addr nonce[0], unsafeAddr nonceBytes, gcmNonceSize)

    var iv: array[ivSize, byte]
    let ivHex = "0x00000000000000000000000000000000"
    let ivBytes = ivHex.hexToByteArray(ivSize)
    copyMem(addr iv[0], unsafeAddr ivBytes, ivSize)

    let (encoded, nonceEnc) = encodeMessagePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, nonce.some, iv.some)
    trace ">>> [New Encoding] Ping Ordinary Message Packet", nonce = nonceEnc, encoded = byteutils.toHex(encoded)

    let decoded = codecB.decodePacket(nodeA.address.get(), encoded)
    check:
      decoded.isOk()
      decoded.get().messageOpt.isSome()
      decoded.get().messageOpt.get().reqId.id == hexToSeqByte(pingReqId)
      decoded.get().messageOpt.get().kind == MessageKind.ping
      decoded.get().messageOpt.get().ping.sprSeq == pingSprSeq

  test "Whoareyou Packet":
    const
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouSprSeq = 0

    var nonce: AESGCMNonce
    let nonceBytes = whoareyouRequestNonce.hexToByteArray(gcmNonceSize)
    copyMem(addr nonce[0], unsafeAddr nonceBytes, gcmNonceSize)

    var idNonce: IdNonce
    let idNonceBytes = whoareyouIdNonce.hexToByteArray(idNonceSize)
    copyMem(addr idNonce[0], unsafeAddr idNonceBytes, idNonceSize)

    var iv: array[ivSize, byte]
    let ivHex = "0x00000000000000000000000000000000"
    let ivBytes = ivHex.hexToByteArray(ivSize)
    copyMem(addr iv[0], unsafeAddr ivBytes, ivSize)

    let
      encoded = encodeWhoareyouPacket(
        rng[],
        codecA,
        nodeB.id,
        nodeB.address.get(),
        nonce,
        whoareyouSprSeq.uint64,
        keys.PublicKey.none,
        idNonce.some,
        iv.some)

    trace ">>> [New Encoding] Whoareyou Packet", nonce, encoded = byteutils.toHex(encoded)

    let decoded = codecB.decodePacket(nodeA.address.get(), encoded)

    check:
      decoded.isOk()
      decoded.get().flag == Flag.Whoareyou
      decoded.get().whoareyou.requestNonce == hexToByteArray[gcmNonceSize](whoareyouRequestNonce)
      decoded.get().whoareyou.idNonce == hexToByteArray[idNonceSize](whoareyouIdNonce)
      decoded.get().whoareyou.recordSeq == whoareyouSprSeq
      decoded.get().whoareyou.challengeData == hexToSeqByte(whoareyouChallengeData)

      codecB.decodePacket(nodeA.address.get(),
        encoded & "00".hexToSeqByte).isErr()

  test "Ping Handshake Message Packet":
    const
      pingReqId = "0x00000001"
      pingSprSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouSprSeq = 1'u64

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouSprSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = some(privKeyA.toPublicKey())
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let
      m = PingMessage(sprSeq: pingSprSeq)
      reqId = RequestId(id: hexToSeqByte(pingReqId))
      message = encodeMessage(m, reqId)

    var nonce: AESGCMNonce
    copyMem(addr nonce[0], unsafeAddr whoareyouData.requestNonce, gcmNonceSize)

    var idNonce: IdNonce
    copyMem(addr idNonce[0], unsafeAddr whoareyouData.idNonce, idNonceSize)

    var iv: array[ivSize, byte]
    let ivHex = "0x00000000000000000000000000000000"
    let ivBytes = ivHex.hexToByteArray(ivSize)
    copyMem(addr iv[0], unsafeAddr ivBytes, ivSize)

    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), nonce, whoareyouSprSeq, pubkey, idNonce.some, iv.some)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let encoded = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, decodedDummy[].whoareyou,
      privKeyB.toPublicKey(), nonce.some, iv.some)

    trace ">>> [New Encoding] Ping Handshake Message Packet", nonce, encoded = byteutils.toHex(encoded)

    let decoded = codecB.decodePacket(nodeA.address.get(), encoded)

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == MessageKind.ping
      decoded.get().message.ping.sprSeq == pingSprSeq
      decoded.get().node.isNone()

      codecB.decodePacket(nodeA.address.get(),
        encoded & "00".hexToSeqByte).isErr()

  test "Ping Handshake Message Packet with SPR":
    const
      pingReqId = "0x00000001"
      pingSprSeq = 1'u64
      #
      # handshake inputs:
      #
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouSprSeq = 0'u64

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouSprSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = none(keys.PublicKey)
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let
      m = PingMessage(sprSeq: pingSprSeq)
      reqId = RequestId(id: hexToSeqByte(pingReqId))
      message = encodeMessage(m, reqId)

    var nonce: AESGCMNonce
    copyMem(addr nonce[0], unsafeAddr whoareyouData.requestNonce, gcmNonceSize)

    var idNonce: IdNonce
    copyMem(addr idNonce[0], unsafeAddr whoareyouData.idNonce, idNonceSize)

    var iv: array[ivSize, byte]
    let ivHex = "0x00000000000000000000000000000000"
    let ivBytes = ivHex.hexToByteArray(ivSize)
    copyMem(addr iv[0], unsafeAddr ivBytes, ivSize)

    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), nonce, whoareyouSprSeq, pubkey, idNonce.some, iv.some)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let encoded = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, decodedDummy[].whoareyou,
      privKeyB.toPublicKey(), nonce.some, iv.some)

    trace ">>> [New Encoding] Ping Handshake Message Packet with SPR", nonce, encoded = byteutils.toHex(encoded)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      encoded)

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == MessageKind.ping
      decoded.get().message.ping.sprSeq == pingSprSeq
      decoded.get().node.isSome()

      codecB.decodePacket(nodeA.address.get(),
        encoded & "00".hexToSeqByte).isErr()

suite "Discovery v5.1 Additional Encode/Decode":
  var rng = keys.newRng()

  test "Encryption/Decryption":
    let
      encryptionKey = hexToByteArray[aesKeySize]("0x9f2d77db7004bf8a1a85107ac686990b")
      nonce = hexToByteArray[gcmNonceSize]("0x27b5af763c446acd2749fe8e")
      ad = hexToByteArray[32]("0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
      pt = hexToSeqByte("0xa1")

    let
      ct = encryptGCM(encryptionKey, nonce, pt, ad)
      decrypted = decryptGCM(encryptionKey, nonce, ct, ad)

    check decrypted.get() == pt

  test "Decryption":
    let
      encryptionKey = hexToByteArray[aesKeySize]("0x9f2d77db7004bf8a1a85107ac686990b")
      nonce = hexToByteArray[gcmNonceSize]("0x27b5af763c446acd2749fe8e")
      ad = hexToByteArray[32]("0x93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
      pt = hexToSeqByte("0x01c20101")
      ct = hexToSeqByte("0xa5d12a2d94b8ccb3ba55558229867dc13bfa3648")

    # valid case
    check decryptGCM(encryptionKey, nonce, ct, ad).get() == pt

    # invalid tag/data sizes
    var invalidCipher: seq[byte] = @[]
    check decryptGCM(encryptionKey, nonce, invalidCipher, ad).isNone()

    invalidCipher = repeat(byte(4), gcmTagSize)
    check decryptGCM(encryptionKey, nonce, invalidCipher, ad).isNone()

    # invalid tag/data itself
    invalidCipher = repeat(byte(4), gcmTagSize + 1)
    check decryptGCM(encryptionKey, nonce, invalidCipher, ad).isNone()

  test "Encrypt / Decrypt header":
    var nonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], nonce)
    let
      privKey = keys.PrivateKey.random(rng[])
      nodeId = privKey.toPublicKey().toNodeId()
      authdata = newSeq[byte](32)
      staticHeader = encodeStaticHeader(Flag.OrdinaryMessage, nonce,
        authdata.len())
      header = staticHeader & authdata

    var iv: array[128 div 8, byte]
    brHmacDrbgGenerate(rng[], iv)

    let
      encrypted = encryptHeader(nodeId, iv, header)
      decoded = decodeHeader(nodeId, iv, encrypted)

    check decoded.isOk()

  var
    codecA, codecB: Codec
    nodeA, nodeB: Node
    privKeyA, privKeyB: keys.PrivateKey

  setup:
    privKeyA = keys.PrivateKey.random(rng[]) # sender -> encode
    privKeyB = keys.PrivateKey.random(rng[]) # receiver -> decode

    let
      enrRecA = SignedPeerRecord.init(1, privKeyA,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")

      enrRecB = SignedPeerRecord.init(1, privKeyB,
        some(ValidIpAddress.init("127.0.0.1")), some(Port(9000)),
        some(Port(9000))).expect("Properly intialized private key")

    nodeA = newNode(enrRecA).expect("Properly initialized record")
    nodeB = newNode(enrRecB).expect("Properly initialized record")
    codecA = Codec(localNode: nodeA, privKey: privKeyA, sessions: Sessions.init(5))
    codecB = Codec(localNode: nodeB, privKey: privKeyB, sessions: Sessions.init(5))

  test "Encode / Decode Ordinary Random Message Packet":
    let
      m = PingMessage(sprSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)

    let (data, nonce) = encodeMessagePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message)

    let decoded = codecB.decodePacket(nodeA.address.get(), data)
    check:
      decoded.isOk()
      decoded[].flag == OrdinaryMessage
      decoded[].messageOpt.isNone()
      decoded[].requestNonce == nonce

  test "Encode / Decode Whoareyou Packet":
    var requestNonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], requestNonce)
    let recordSeq = 0'u64

    let data = encodeWhoareyouPacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), requestNonce, recordSeq, none(keys.PublicKey))

    let decoded = codecB.decodePacket(nodeA.address.get(), data)

    let key = HandshakeKey(nodeId: nodeB.id, address: nodeB.address.get())
    var challenge: Challenge

    check:
      codecA.handshakes.pop(key, challenge)
      decoded.isOk()
      decoded[].flag == Flag.Whoareyou
      decoded[].whoareyou.requestNonce == requestNonce
      decoded[].whoareyou.idNonce == challenge.whoareyouData.idNonce
      decoded[].whoareyou.recordSeq == recordSeq

  test "Encode / Decode Handshake Message Packet":
    var requestNonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], requestNonce)
    let
      recordSeq = 1'u64
      m = PingMessage(sprSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)
      pubkey = some(privKeyA.toPublicKey())

    # Encode/decode whoareyou packet to get the handshake stored and the
    # whoareyou data returned. It's either that or construct the header for the
    # whoareyouData manually.
    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), requestNonce, recordSeq, pubkey)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let data = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, decodedDummy[].whoareyou,
      privKeyB.toPublicKey())

    let decoded = codecB.decodePacket(nodeA.address.get(), data)

    check:
      decoded.isOk()
      decoded.get().message.reqId == reqId
      decoded.get().message.kind == MessageKind.ping
      decoded.get().message.ping.sprSeq == 0
      decoded.get().node.isNone()

  test "Encode / Decode Handshake Message Packet with SPR":
    var requestNonce: AESGCMNonce
    brHmacDrbgGenerate(rng[], requestNonce)
    let
      recordSeq = 0'u64
      m = PingMessage(sprSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)
      pubkey = none(keys.PublicKey)

    # Encode/decode whoareyou packet to get the handshake stored and the
    # whoareyou data returned. It's either that or construct the header for the
    # whoareyouData manually.
    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), requestNonce, recordSeq, pubkey)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let encoded = encodeHandshakePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message, decodedDummy[].whoareyou,
      privKeyB.toPublicKey())

    let decoded = codecB.decodePacket(nodeA.address.get(), encoded)

    check:
      decoded.isOk()
      decoded.get().message.reqId == reqId
      decoded.get().message.kind == MessageKind.ping
      decoded.get().message.ping.sprSeq == 0
      decoded.get().node.isSome()
      decoded.get().node.get().record.seqNum == 1

  test "Encode / Decode Ordinary Message Packet":
    let
      m = PingMessage(sprSeq: 0)
      reqId = RequestId.init(rng[])
      message = encodeMessage(m, reqId)

    # Need to manually add the secrets that normally get negotiated in the
    # handshake packet.
    var secrets: HandshakeSecrets
    codecA.sessions.store(nodeB.id, nodeB.address.get(), secrets.recipientKey,
      secrets.initiatorKey)
    codecB.sessions.store(nodeA.id, nodeA.address.get(), secrets.initiatorKey,
      secrets.recipientKey)

    let (data, nonce) = encodeMessagePacket(rng[], codecA, nodeB.id,
      nodeB.address.get(), message)

    let decoded = codecB.decodePacket(nodeA.address.get(), data)
    check:
      decoded.isOk()
      decoded.get().flag == OrdinaryMessage
      decoded.get().messageOpt.isSome()
      decoded.get().messageOpt.get().reqId == reqId
      decoded.get().messageOpt.get().kind == MessageKind.ping
      decoded.get().messageOpt.get().ping.sprSeq == 0
      decoded[].requestNonce == nonce
