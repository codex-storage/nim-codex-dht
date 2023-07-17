# codex-dht - Codex DHT
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import std/sequtils

import pkg/chronicles
import pkg/libp2p

import ../node
import ../lru
import ./common

const
  MaxProvidersEntries* = 1000'u # one thousand records
  MaxProvidersPerEntry* = 200'u  # providers per entry

logScope:
  topics = "discv5 providers cache"

type
  Providers* = LRUCache[PeerId, SignedPeerRecord]
  ItemsCache* = LRUCache[NodeId, Providers]

  ProvidersCache* = object
    disable: bool
    cache*: ItemsCache
    maxProviders*: int

func add*(
  self: var ProvidersCache,
  id: NodeId,
  provider: SignedPeerRecord) =

  if self.disable:
    return

  var providers =
    if id notin self.cache:
      Providers.init(self.maxProviders.int)
    else:
      self.cache.get(id).get()

  let
    peerId = provider.data.peerId

  trace "Adding provider to cache", id, peerId
  providers.put(peerId, provider)
  self.cache.put(id, providers)

proc get*(
  self: var ProvidersCache,
  id: NodeId,
  start = 0,
  stop = MaxProvidersPerEntry.int): seq[SignedPeerRecord] =

  if self.disable:
    return

  if id in self.cache:
    let
      recs = self.cache.get(id).get

    let
      providers = toSeq(recs)[start..<min(recs.len, stop)]

    trace "Providers already cached", id, len = providers.len
    return providers

func remove*(
  self: var ProvidersCache,
  id: NodeId,
  peerId: PeerId) =

  if self.disable:
    return

  if id notin self.cache:
    return

  var
    providers = self.cache.get(id).get()

  trace "Removing provider from cache", id
  providers.del(peerId)
  self.cache.put(id, providers)

func drop*(self: var ProvidersCache, id: NodeId) =
  if self.disable:
    return

  self.cache.del(id)

func init*(
  T: type ProvidersCache,
  size = MaxProvidersEntries,
  maxProviders = MaxProvidersEntries,
  disable = false): T =

  T(
    cache: ItemsCache.init(size.int),
    maxProviders: maxProviders.int,
    disable: disable)
