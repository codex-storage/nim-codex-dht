# codex-dht - Codex DHT
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## Session cache as mentioned at
## https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md#session-cache
##

## A session stores encryption and decryption keys for P2P encryption.
## Since key exchange can be started both ways, and these might not get finalised with
## UDP transport, we can't be sure what encryption key will be used by the other side:
## - the one derived in the key-exchange started by us,
## - the one derived in the key-exchange started by the other node.
## To alleviate this issue, we store two decryption keys in each session.

{.push raises: [].}

import
  std/options,
  stint, stew/endians2, stew/shims/net,
  node, lru

export lru

const
  aesKeySize* = 128 div 8
  keySize = sizeof(NodeId) +
            16 + # max size of ip address (ipv6)
            2 # Sizeof port

type
  AesKey* = array[aesKeySize, byte]
  SessionKey* = array[keySize, byte]
  SessionValue* = array[3 * sizeof(AesKey), byte]
  Sessions* = LRUCache[SessionKey, SessionValue]

func makeKey(id: NodeId, address: Address): SessionKey =
  var pos = 0
  result[pos ..< pos+sizeof(id)] = toBytesBE(id)
  pos.inc(sizeof(id))
  case address.ip.family
  of IpAddressFamily.IpV4:
    result[pos ..< pos+sizeof(address.ip.address_v4)] = address.ip.address_v4
  of IpAddressFamily.IpV6:
    result[pos ..< pos+sizeof(address.ip.address_v6)] = address.ip.address_v6
  pos.inc(sizeof(address.ip.address_v6))
  result[pos ..< pos+sizeof(address.port)] = toBytesBE(address.port.uint16)

func swapr*(s: var Sessions, id: NodeId, address: Address) =
  var value: array[3 * sizeof(AesKey), byte]
  let
    key = makeKey(id, address)
    entry = s.get(key)
  if entry.isSome():
    let val = entry.get()
    copyMem(addr value[0], unsafeAddr val[16], sizeof(AesKey))
    copyMem(addr value[16], unsafeAddr val[0], sizeof(AesKey))
    copyMem(addr value[32], unsafeAddr val[32], sizeof(AesKey))
    s.put(key, value)

func store*(s: var Sessions, id: NodeId, address: Address, r, w: AesKey) =
  var value: array[3 * sizeof(AesKey), byte]
  let
    key = makeKey(id, address)
    entry = s.get(key)
  if entry.isSome():
    let val = entry.get()
    copyMem(addr value[0], unsafeAddr val[16], sizeof(r))
  value[16 .. 31] = r
  value[32 .. ^1] = w
  s.put(key, value)

func load*(s: var Sessions, id: NodeId, address: Address, r1, r2, w: var AesKey): bool =
  let res = s.get(makeKey(id, address))
  if res.isSome():
    let val = res.get()
    copyMem(addr r1[0], unsafeAddr val[0], sizeof(r1))
    copyMem(addr r2[0], unsafeAddr val[sizeof(r1)], sizeof(r2))
    copyMem(addr w[0], unsafeAddr val[sizeof(r1) + sizeof(r2)], sizeof(w))
    return true
  else:
    return false

func del*(s: var Sessions, id: NodeId, address: Address) =
  s.del(makeKey(id, address))
