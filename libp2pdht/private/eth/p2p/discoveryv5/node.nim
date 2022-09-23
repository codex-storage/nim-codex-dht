# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/hashes,
  bearssl,
  chronicles,
  chronos,
  nimcrypto,
  stew/shims/net,
  stint,
  ./crypto,
  ./spr

export stint

type
  NodeId* = UInt256

  Address* = object
    ip*: ValidIpAddress
    port*: Port

  Node* = ref object
    id*: NodeId
    pubkey*: PublicKey
    address*: Option[Address]
    record*: SignedPeerRecord
    seen*: bool ## Indicates if there was at least one successful
    ## request-response with this node, or if the nde was verified
    ## through the underlying transport mechanisms.

func toNodeId*(pid: PeerId): NodeId =
  ## Convert public key to a node identifier.
  # Keccak256 hash is used as defined in SPR spec for scheme v4:
  # https://github.com/ethereum/devp2p/blob/master/enr.md#v4-identity-scheme
  readUintBE[256](keccak256.digest(pid.data).data)

proc toNodeId*(pk: PublicKey): Result[NodeId, cstring] =
  let pid = ? PeerId.init(pk)
  ok pid.toNodeId

func newNode*(r: SignedPeerRecord): Result[Node, cstring] =
  ## Create a new `Node` from a `SignedPeerRecord`.
  # TODO: Handle IPv6

  let pk = r.get(PublicKey)
  # This check is redundant for a properly created record as the deserialization
  # of a record will fail at `verifySignature` if there is no public key.
  if pk.isNone():
    return err("Could not recover public key from SPR")

  # Also this can not fail for a properly created record as id is checked upon
  # deserialization.
  let
    tr = ? r.toTypedRecord()
    nodeId = ? pk.get().toNodeId()

  if tr.ip.isSome() and tr.udp.isSome():
    let a = Address(ip: ipv4(tr.ip.get()), port: Port(tr.udp.get()))

    ok(Node(id: nodeId, pubkey: pk.get() , record: r,
       address: some(a)))
  else:
    ok(Node(id: nodeId, pubkey: pk.get(), record: r,
       address: none(Address)))

proc update*(n: Node, pk: PrivateKey, ip: Option[ValidIpAddress],
    tcpPort, udpPort: Option[Port] = none[Port]()): Result[void, cstring] =
  ? n.record.update(pk, ip, tcpPort, udpPort)

  if ip.isSome():
    if udpPort.isSome():
      let a = Address(ip: ip.get(), port: udpPort.get())
      n.address = some(a)
    elif n.address.isSome():
      let a = Address(ip: ip.get(), port: n.address.get().port)
      n.address = some(a)
    else:
      n.address = none(Address)
  else:
    n.address = none(Address)

  ok()

func hash*(n: Node): hashes.Hash =
  hash(n.pubkey.getRawBytes.expect("Public key has correct structure"))

func `==`*(a, b: Node): bool =
  (a.isNil and b.isNil) or
    (not a.isNil and not b.isNil and a.pubkey == b.pubkey)

func hash*(id: NodeId): Hash =
  hash(id.toByteArrayBE)

proc random*(T: type NodeId, rng: var BrHmacDrbgContext): T =
  var id: NodeId
  brHmacDrbgGenerate(addr rng, addr id, csize_t(sizeof(id)))

  id

func `$`*(id: NodeId): string =
  id.toHex()

func shortLog*(id: NodeId): string =
  ## Returns compact string representation of ``id``.
  var sid = $id
  if len(sid) <= 10:
    result = sid
  else:
    result = newStringOfCap(10)
    for i in 0..<2:
      result.add(sid[i])
    result.add("*")
    for i in (len(sid) - 6)..sid.high:
      result.add(sid[i])
chronicles.formatIt(NodeId): shortLog(it)

func hash*(ip: ValidIpAddress): Hash =
  case ip.family
  of IpAddressFamily.IPv6: hash(ip.address_v6)
  of IpAddressFamily.IPv4: hash(ip.address_v4)

func hash*(a: Address): hashes.Hash =
  let res = a.ip.hash !& a.port.hash
  !$res

func `$`*(a: Address): string =
  result.add($a.ip)
  result.add(":" & $a.port)

func shortLog*(n: Node): string =
  if n.isNil:
    "uninitialized"
  elif n.address.isNone():
    shortLog(n.id) & ":unaddressable"
  else:
    shortLog(n.id) & ":" & $n.address.get()
chronicles.formatIt(Node): shortLog(it)

func shortLog*(nodes: seq[Node]): string =
  result = "["

  var first = true
  for n in nodes:
    if first:
      first = false
    else:
      result.add(", ")
    result.add(shortLog(n))

  result.add("]")
chronicles.formatIt(seq[Node]): shortLog(it)
