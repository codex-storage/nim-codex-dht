# codex-dht - Codex DHT
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## Discovery v5 Protocol Messages as specified at
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#protocol-messages
## These messages get protobuf encoded, while in the spec they get RLP encoded.
##

{.push raises: [Defect].}

import
  std/[hashes, net],
  bearssl/rand,
  ./spr,
  ./node,
  ../../../../dht/providers_messages

export providers_messages

type
  MessageKind* {.pure.} = enum
    # TODO This is needed only to make Nim 1.2.6 happy
    #      Without it, the `MessageKind` type cannot be used as
    #      a discriminator in case objects.
    unused = 0x00

    ping = 0x01
    pong = 0x02
    findNode = 0x03
    nodes = 0x04
    talkReq = 0x05
    talkResp = 0x06
    regTopic = 0x07
    ticket = 0x08
    regConfirmation = 0x09
    topicQuery = 0x0A
    addProvider = 0x0B
    getProviders = 0x0C
    providers = 0x0D
    findNodeFast = 0x83

  RequestId* = object
    id*: seq[byte]

  PingMessage* = object
    sprSeq*: uint64

  PongMessage* = object
    sprSeq*: uint64
    ip*: IpAddress
    port*: uint16

  FindNodeMessage* = object
    distances*: seq[uint16]

  FindNodeFastMessage* = object
    target*: NodeId

  NodesMessage* = object
    total*: uint32
    sprs*: seq[SignedPeerRecord]

  TalkReqMessage* = object
    protocol*: seq[byte]
    request*: seq[byte]

  TalkRespMessage* = object
    response*: seq[byte]

  # Not implemented, specification is not final here.
  RegTopicMessage* = object
  TicketMessage* = object
  RegConfirmationMessage* = object
  TopicQueryMessage* = object

  SomeMessage* = PingMessage or PongMessage or FindNodeMessage or NodesMessage or
    TalkReqMessage or TalkRespMessage or AddProviderMessage or GetProvidersMessage or
    ProvidersMessage or FindNodeFastMessage

  Message* = object
    reqId*: RequestId
    case kind*: MessageKind
    of ping:
      ping*: PingMessage
    of pong:
      pong*: PongMessage
    of findNode:
      findNode*: FindNodeMessage
    of findNodeFast:
      findNodeFast*: FindNodeFastMessage
    of nodes:
      nodes*: NodesMessage
    of talkReq:
      talkReq*: TalkReqMessage
    of talkResp:
      talkResp*: TalkRespMessage
    of regTopic:
      regtopic*: RegTopicMessage
    of ticket:
      ticket*: TicketMessage
    of regConfirmation:
      regConfirmation*: RegConfirmationMessage
    of topicQuery:
      topicQuery*: TopicQueryMessage
    of addProvider:
      addProvider*: AddProviderMessage
    of getProviders:
      getProviders*: GetProvidersMessage
    of providers:
      provs*: ProvidersMessage
    else:
      discard

template messageKind*(T: typedesc[SomeMessage]): MessageKind =
  when T is PingMessage: MessageKind.ping
  elif T is PongMessage: MessageKind.pong
  elif T is FindNodeMessage: MessageKind.findNode
  elif T is FindNodeFastMessage: MessageKind.findNodeFast
  elif T is NodesMessage: MessageKind.nodes
  elif T is TalkReqMessage: MessageKind.talkReq
  elif T is TalkRespMessage: MessageKind.talkResp
  elif T is AddProviderMessage: MessageKind.addProvider
  elif T is GetProvidersMessage: MessageKind.getProviders
  elif T is ProvidersMessage: MessageKind.providers

proc hash*(reqId: RequestId): Hash =
  hash(reqId.id)

proc init*(T: type RequestId, rng: var HmacDrbgContext): T =
  var reqId = RequestId(id: newSeq[byte](8)) # RequestId must be <= 8 bytes
  hmacDrbgGenerate(rng, reqId.id)
  reqId
