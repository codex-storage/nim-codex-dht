# codex-dht - Codex DHT
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import std/sequtils
import std/strutils

import pkg/chronos
import pkg/libp2p
import pkg/datastore
import pkg/questionable
import pkg/questionable/results

import ../node

export node, results

const
  ProvidersKey* = Key.init("/providers").tryGet # keys is of the form /providers/peerid = provider
  CidKey* = Key.init("/cids").tryGet            # keys is of the form /cids/cid/peerid/ttl = ttl

  ZeroMoment* = Moment.init(0, Nanosecond) # for conversion between Duration and Moment

proc mapFailure*[T](err: T): ref CatchableError =
  newException(CatchableError, $err)

proc makeProviderKey*(peerId: PeerId): ?!Key =
  (ProvidersKey / $peerId)

proc makeCidKey*(cid: NodeId, peerId: PeerId): ?!Key =
  (CidKey / cid.toHex / $peerId / "ttl")

proc fromCidKey*(key: Key): ?!tuple[id: NodeId, peerId: PeerId] =
  let
    parts = key.id.split(datastore.Separator)

  if parts.len == 5:
    let
      peerId = ?PeerId.init(parts[3]).mapErr(mapFailure)
      id = ?NodeId.fromHex(parts[2]).catch

    return success (id, peerId)

  return failure("Unable to extract peer id from key")

proc fromProvKey*(key: Key): ?!PeerId =
  let
    parts = key.id.split(datastore.Separator)

  if parts.len != 3:
    return failure("Can't find peer id in key")

  return success ?PeerId.init(parts[^1]).mapErr(mapFailure)
