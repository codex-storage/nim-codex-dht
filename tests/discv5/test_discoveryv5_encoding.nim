{.used.}

import
  std/[options, sequtils, tables],
  asynctest/unittest2,
  bearssl,
  chronos,
  eth/rlp,
  libp2p/crypto/secp,
  libp2pdht/discv5/[messages, messages_encoding, encoding, spr, node, sessions],
  libp2pdht/discv5/crypto,
  stew/byteutils,
  stew/shims/net,
  stint,
  ../dht/test_helper

from secp256k1 import toRaw

suite "Discovery v5.1 Protocol Message Encodings":
  test "Ping Request":
    let
      sprSeq = 1'u64
      p = PingMessage(sprSeq: sprSeq)
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(p, reqId)
    check byteutils.toHex(encoded) == "01c20101"

    let decoded = decodeMessage(encoded)
    check decoded.isOk()

    let message = decoded.get()
    check:
      message.reqId == reqId
      message.kind == ping
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
      message.kind == findNode
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
    check s1.fromURI("spr:CiUIAhIhAjOdSH7SNzktg3kZUNyJHwY23mmMH6BR6gGuP6WL14WAEgIDARpWCicAJQgCEiECM51IftI3OS2DeRlQ3IkfBjbeaYwfoFHqAa4_pYvXhYAQnP2JkgYaCwoJBAAAAACRAgABGgsKCQQAAAAAkQIAAhoLCgkEAAAAAJECAAMqRzBFAiEAjMd_0mXjPJVRdLn0ligEiy1ypjlayzDwup2QU2-hpdUCIH-o5bq46N3umISo4kSwmQIo41RrWptoSGMqvZJHluV2")
    check s2.fromURI("spr:CiUIAhIhAmvtpc_d8c2JEw57W7YJK6wj20oES_hHMoqgMQ3RI6RFEgIDARpWCicAJQgCEiECa-2lz93xzYkTDntbtgkrrCPbSgRL-EcyiqAxDdEjpEUQnP2JkgYaCwoJBAAAAACRAgABGgsKCQQAAAAAkQIAAhoLCgkEAAAAAJECAAMqRjBEAiA9QbGnjF5tmMm08_yyE9wWrk3lChyHFaspxRav5kiLTgIgWEHQnpKz0vGtcse8Bm5WHatXMgiG8_u_Jy0s8XMsolk")
    let
      total = 0x1'u32
      n = NodesMessage(total: total, sprs: @[s1, s2])
      reqId = RequestId(id: @[1.byte])

    let encoded = encodeMessage(n, reqId)
    check byteutils.toHex(encoded) == "04f901a00101f9019bb8cc0a250802122102339d487ed237392d83791950dc891f0636de698c1fa051ea01ae3fa58bd78580120203011a560a2700250802122102339d487ed237392d83791950dc891f0636de698c1fa051ea01ae3fa58bd78580109cfd8992061a0b0a090400000000910200011a0b0a090400000000910200021a0b0a090400000000910200032a4730450221008cc77fd265e33c955174b9f49628048b2d72a6395acb30f0ba9d90536fa1a5d502207fa8e5bab8e8ddee9884a8e244b0990228e3546b5a9b6848632abd924796e576b8cb0a2508021221026beda5cfddf1cd89130e7b5bb6092bac23db4a044bf847328aa0310dd123a445120203011a560a27002508021221026beda5cfddf1cd89130e7b5bb6092bac23db4a044bf847328aa0310dd123a445109cfd8992061a0b0a090400000000910200011a0b0a090400000000910200021a0b0a090400000000910200032a46304402203d41b1a78c5e6d98c9b4f3fcb213dc16ae4de50a1c8715ab29c516afe6488b4e02205841d09e92b3d2f1ad72c7bc066e561dab57320886f3fbbf272d2cf1732ca259"

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
      message.kind == talkReq
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
    check byteutils.toHex(encoded) == "01cb8900010203040506070801"

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
      pub = PublicKey.fromHex(publicKey).expect("Valid public key hex")
      priv = PrivateKey.fromHex(secretKey).expect("Valid private key hex")
      eph = ecdhRaw(priv, pub).expect("Valid public and private keys")
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
      PrivateKey.fromHex(ephemeralKey).expect("Valid private key hex"),
      PublicKey.fromHex(destPubkey).expect("Valid public key hex"),
      hexToSeqByte(challengeData)
    ).expect("Valid key structure")

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
      idSignature = "0xdb0ae930a460fd767cb26a519221e6be5edc3501865406d8af6d215f87ebf35b07563d891082d97147d9499f49bb86ee399f57367af1b866674f9e54760e3a21"

    let
      privKey = PrivateKey.fromHex(staticKey).expect("Valid private key hex")
      signature = createIdSignature(
        privKey,
        hexToSeqByte(challengeData),
        hexToSeqByte(ephemeralPubkey),
        NodeId.fromHex(nodeIdB)
      ).expect("Valid signature data")
      libp2pSig = SkSignature.init(signature.data).expect("Valid sig data")
      skSig = secp256k1.SkSignature(libp2pSig)
    check:
      skSig.toRaw() == hexToByteArray[64](idSignature)
      verifyIdSignature(signature, hexToSeqByte(challengeData),
        hexToSeqByte(ephemeralPubkey), NodeId.fromHex(nodeIdB),
        privKey.getPublicKey.expect("Valid private key for public key"))

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
    privKeyA, privKeyB: PrivateKey

  setup:
    # sender -> encode
    privKeyA = PrivateKey.fromHex(nodeAKey).expect("Valid private key hex")
    # receive -> decode
    privKeyB = PrivateKey.fromHex(nodeBKey).expect("Valid private key hex")

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
        "000000000000000000000000000000003788c1e1079e89374c4beac74d76364d" &
        "bd9e8cd1847adc2f49fbacc6862425583586c023b19b6fdd1d836777ee39fee8" &
        "7afd279a5fe4ffdded6d1a6d388217da82d38761b60b0c6e9dd94a8713bc5d"

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
      decoded.get().messageOpt.get().kind == ping
      decoded.get().messageOpt.get().ping.sprSeq == pingSprSeq

  test "Whoareyou Packet":
    const
      whoareyouChallengeData = "0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000"
      whoareyouRequestNonce = "0x0102030405060708090a0b0c"
      whoareyouIdNonce = "0x0102030405060708090a0b0c0d0e0f10"
      whoareyouSprSeq = 0

      encodedPacket =
        "000000000000000000000000000000003788c1e1079e89374d4beac74d76364d" &
        "bd9e8cd1847ae48d2f96e595c7a904454033dd25eaefc076a4537f17e8a43a"

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
        "000000000000000000000000000000003788c1e1079e89374e4beac74d76364d" &
        "bd9e8cd1847a712f49fbacc6862425583586c023b19b6fdd1d836777ee39fee8" &
        "7afd279a5fe4ff441af3b17ec968350f37edbda9e0ba8ac0fd2617ef67a1e362" &
        "5ea8eb284a3ca85f7ef976ccf2e87932ffeada775849d7aca378033b7a75dbe8" &
        "7cc1767123bb7d7e5d96b5d6ad7c26cb55f6160b250d042ef1b9e6000191ce4e" &
        "a93234ca3de051518684902e70e6a47eb8f0c2efeca8e42d2ea7f5bd1f27c12d" &
        "ae3c579ddcef630659089c99"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouSprSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = privKeyA.getPublicKey
                .expect("Valid private key for public key")
                .some
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == ping
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
        "000000000000000000000000000000003788c1e1079e89374e4beac74d76364d" &
        "bd9e8cd1847bc02f49fbacc6862425583586c023b19b6fdd1d836777ee39fee8" &
        "7afd279a5fe4ff451af3b07ec8407cedec19c57a8460e08d3d8a908f78261170" &
        "68196e7df56279e7493fbb2076025b395dde6ffeecc45daa59def06c9be97b1f" &
        "95636fb8f16887cf13b4a8cca0bcaf805fe62529ad86c59204e73917cf183d19" &
        "847617448722cc8c0eea80b68653e858eff5d250abbd55315db21fac1485db8f" &
        "deaadba582d43c88f0b25512a5fd8395bd2f9519362d29cceb29028de04e0076" &
        "4f6aece318e26e2d123888e484cb1c0ce37ecfee42ced9a811966bae40f40e9d" &
        "4b46e27c388330304409a405b6455547661361d2129aa7bed4ff26f68d53532d" &
        "cb6bae00506a7c5161b0652afcbf2416e97116bdcf9a7a548d6d8b5b0ab2ed0e" &
        "b7a737afc0dbf65f32fd22c27cb17ebfe3c0d43e9bf45cfd24170c9fea348b10" &
        "1207010ad51e28040b46770c1e96e22e7c552a6f1a62b4e29f8c99"

    let
      whoareyouData = WhoareyouData(
        requestNonce: hexToByteArray[gcmNonceSize](whoareyouRequestNonce),
        idNonce: hexToByteArray[idNonceSize](whoareyouIdNonce),
        recordSeq: whoareyouSprSeq,
        challengeData: hexToSeqByte(whoareyouChallengeData))
      pubkey = none(PublicKey)
      challenge = Challenge(whoareyouData: whoareyouData, pubkey: pubkey)
      key = HandshakeKey(nodeId: nodeA.id, address: nodeA.address.get())

    check: not codecB.handshakes.hasKeyOrPut(key, challenge)

    let decoded = codecB.decodePacket(nodeA.address.get(),
      hexToSeqByte(encodedPacket))

    check:
      decoded.isOk()
      decoded.get().message.reqId.id == hexToSeqByte(pingReqId)
      decoded.get().message.kind == ping
      decoded.get().message.ping.sprSeq == pingSprSeq
      decoded.get().node.isSome()

      codecB.decodePacket(nodeA.address.get(),
        hexToSeqByte(encodedPacket & "00")).isErr()

suite "Discovery v5.1 Additional Encode/Decode":
  var rng = newRng()

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
      nodeId = NodeId.example(rng)
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
    privKeyA, privKeyB: PrivateKey

  setup:
    privKeyA = PrivateKey.example(rng) # sender -> encode
    privKeyB = PrivateKey.example(rng) # receiver -> decode

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
      nodeB.address.get(), requestNonce, recordSeq, none(PublicKey))

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
      pubkey = privKeyA.getPublicKey
                 .expect("Valid private key for public key")
                 .some

    # Encode/decode whoareyou packet to get the handshake stored and the
    # whoareyou data returned. It's either that or construct the header for the
    # whoareyouData manually.
    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), requestNonce, recordSeq, pubkey)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let
      pubKeyB = privKeyB.getPublicKey.expect("Valid private key for public key")
      data = encodeHandshakePacket(rng[], codecA, nodeB.id,
               nodeB.address.get(), message, decodedDummy[].whoareyou,
               pubKeyB
             ).expect("Valid handshake packet data")

    let decoded = codecB.decodePacket(nodeA.address.get(), data)

    check:
      decoded.isOk()
      decoded.get().message.reqId == reqId
      decoded.get().message.kind == ping
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
      pubkey = none(PublicKey)

    # Encode/decode whoareyou packet to get the handshake stored and the
    # whoareyou data returned. It's either that or construct the header for the
    # whoareyouData manually.
    let
      encodedDummy = encodeWhoareyouPacket(rng[], codecB, nodeA.id,
        nodeA.address.get(), requestNonce, recordSeq, pubkey)
      decodedDummy = codecA.decodePacket(nodeB.address.get(), encodedDummy)

    let
      pubKeyB = privKeyB.getPublicKey.expect("Valid private key for public key")
      encoded = encodeHandshakePacket(rng[], codecA, nodeB.id,
                  nodeB.address.get(), message, decodedDummy[].whoareyou,
                  pubKeyB
                ).expect("Valid handshake packet data")

    let decoded = codecB.decodePacket(nodeA.address.get(), encoded)

    check:
      decoded.isOk()
      decoded.get().message.reqId == reqId
      decoded.get().message.kind == ping
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
      decoded.get().messageOpt.get().kind == ping
      decoded.get().messageOpt.get().ping.sprSeq == 0
      decoded[].requestNonce == nonce
