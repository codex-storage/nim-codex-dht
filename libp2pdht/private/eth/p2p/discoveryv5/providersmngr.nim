# codex-dht - Codex DHT
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/sequtils
import std/strutils

import pkg/datastore
import pkg/chronos
import pkg/libp2p
import pkg/chronicles
import pkg/stew/results as rs
import pkg/stew/byteutils
import pkg/questionable
import pkg/questionable/results

{.push raises: [Defect].}

import ./lru
import ./node

export node, lru, datastore

const
  DefaultProviderTTL = 24.hours

  ProvidersKey* = Key.init("/providers").tryGet # keys is of the form /providers/peerid = provider
  CidKey* = Key.init("/cids").tryGet            # keys is of the form /cids/cid/peerid/ttl = ttl

  MaxProvidersEntries* = 1000'u # one thousand records
  MaxProvidersPerEntry* = 200'u  # providers per entry

  ZeroMoment = Moment.init(0, Nanosecond) # for conversion between Duration and Moment

type
  ProvidersCache* = LRUCache[PeerId, SignedPeerRecord]
  ItemsCache* = LRUCache[NodeId, ProvidersCache]

  ProvidersManager* = ref object of RootObj
    store*: Datastore
    providers*: ItemsCache
    ttl*: Duration
    maxItems*: uint
    maxProviders*: uint
    disableCache*: bool

proc mapFailure[T](err: T): ref CatchableError =
  newException(CatchableError, $err)

proc makeProviderKey(peerId: PeerId): ?!Key =
  (ProvidersKey / $peerId)

proc makeCidKey(cid: NodeId, peerId: PeerId): ?!Key =
  (CidKey / cid.toHex / $peerId / "ttl")

func addCache*(
  self: ProvidersManager,
  cid: NodeId,
  provider: SignedPeerRecord) =

  if self.disableCache:
    return

  var providers =
    if cid notin self.providers:
      ProvidersCache.init(self.maxProviders.int)
    else:
      self.providers.get(cid).get()

  providers.put(provider.data.peerId, provider)
  self.providers.put(cid, providers)

func removeCache*(
  self: ProvidersManager,
  cid: NodeId,
  peerId: PeerId) =

  if self.disableCache:
    return

  if cid notin self.providers:
    return

  var
    providers = self.providers.get(cid).get()

  providers.del(peerId)
  self.providers.put(cid, providers)

proc decode(
  self: ProvidersManager,
  bytes: seq[byte]): ?!SignedPeerRecord =

  let
    envelope = ?Envelope.decode(bytes, PeerRecord.payloadDomain()).mapErr(mapFailure)
    provider = ?SignedPeerRecord.decode(envelope.payload).mapErr(mapFailure)

  return success provider

proc getProvByKey*(self: ProvidersManager, key: Key): Future[?!SignedPeerRecord] {.async.} =

  without bytes =? (await self.store.get(key)) or bytes.len <= 0:
    trace "No provider in store"
    return failure("No no provider in store")

  return self.decode(bytes)

proc add*(
  self: ProvidersManager,
  cid: NodeId,
  provider: SignedPeerRecord): Future[?!void] {.async.} =
  let peerId = provider.data.peerId

  trace "Adding provider to persistent store", cid, peerId
  without provKey =? makeProviderKey(peerId), err:
    trace "Error creating key from provider record", err = err.msg
    return failure err.msg

  without cidKey =? makeCidKey(cid, peerId), err:
    trace "Error creating key from content id", err = err.msg
    return failure err.msg

  let
    expires = (self.ttl + (Moment.now() - ZeroMoment)).seconds.uint64
    ttl = expires.toBytesBE
    bytes: seq[byte] =
      if existing =? (await self.getProvByKey(provKey)) and
        existing.data.seqNo >= provider.data.seqNo:
        trace "Provider with same seqNo already exist", seqno = $provider.data.seqNo
        @[]
      else:
        without bytes =? provider.envelope.encode:
          trace "Enable to encode provider"
          return failure "Unable to encode provider"
        bytes

  if bytes.len > 0:
    trace "Adding or updating provider record", cid, peerId

    if (let res = (await self.store.put(provKey, bytes)); res.isErr):
      trace "Unable to store provider with key", key = provKey

  let
    res = (await self.store.put(cidKey, @ttl)) # add/update cid ttl

  if res.isOk:
    self.addCache(cid, provider)

  return res

proc get*(
  self: ProvidersManager,
  id: NodeId,
  limit = MaxProvidersPerEntry.int): Future[?!seq[SignedPeerRecord]] {.async.} =

  if id in self.providers:
    let recs = self.providers.get(id).get
    return success toSeq(recs)[0..<min(recs.len, limit)]

  without cidKey =? (CidKey / id.toHex), err:
    return failure err.msg

  without iter =?
    (await self.store.query(Query.init(cidKey, limit = limit))), err:
    return failure err.msg

  defer:
    discard (await iter.dispose())

  var providers: seq[SignedPeerRecord]
  for item in iter:
    if pair =? (await item) and pair.key.isSome:
      let (key, data) = pair

      if provider =? self.decode(data):
        trace "Retrieved provider with", key = key.get()
        providers.add(provider)
        self.addCache(id, provider)

  return success providers

proc contains*(
  self: ProvidersManager,
  id: NodeId,
  peerId: PeerId): Future[bool] {.async.} =
  without key =? makeCidKey(id, peerId), err:
    return false

  return (await self.store.contains(key)) |? false

proc contains*(self: ProvidersManager, peerId: PeerId): Future[bool] {.async.} =
  without provKey =? makeProviderKey(peerId), err:
    return false

  return (await self.store.contains(provKey)) |? false

proc contains*(self: ProvidersManager, cid: NodeId): Future[bool] {.async.} =
  without cidKey =? (CidKey / $cid), err:
    return false

  let
    q = Query.init(cidKey, limit = 1)

  without iter =? (await self.store.query(q)), err:
    trace "Unable to obtain record for key", key = cidKey
    return false

  defer:
    trace "Cleaning up query iterator"
    discard (await iter.dispose())

  for item in iter:
    if pair =? (await item) and pair.key.isSome:
      return true

  return false

proc remove*(self: ProvidersManager, cid: NodeId): Future[?!void] {.async.} =

  if cid in self.providers:
    self.providers.del(cid)

  without cidKey =? (CidKey / $cid), err:
    return failure(err.msg)

  let
    q = Query.init(cidKey)

  without iter =? (await self.store.query(q)), err:
    trace "Unable to obtain record for key", key = cidKey
    return failure(err.msg)

  block:
    defer:
      trace "Cleaning up query iterator"
      discard (await iter.dispose())

    for item in iter:
      if pair =? (await item) and pair.key.isSome:
        let key = pair.key.get()
        if (
          let res = (await self.store.delete(key));
          res.isErr):
          trace "Error deleting record from persistent store", err = res.error.msg
          continue

        trace "Deleted record from store", key

  return success()

proc remove*(self: ProvidersManager, peerId: PeerId): Future[?!void] {.async.} =
  without cidKey =? (CidKey / "*" / $peerId), err:
    return failure(err.msg)

  let
    q = Query.init(cidKey)

  without iter =? (await self.store.query(q)), err:
    trace "Unable to obtain record for key", key = cidKey
    return failure(err.msg)

  block:
    defer:
      trace "Cleaning up query iterator"
      discard (await iter.dispose())

    for item in iter:
      if pair =? (await item) and pair.key.isSome:
        let
          key = pair.key.get()

        if (
          let res = (await self.store.delete(key));
          res.isErr):
            trace "Error deleting record from persistent store", err = res.error.msg
            continue

        trace "Deleted record from store", key

        let
          parts = key.id.split(datastore.Separator)

        self.removeCache(NodeId.fromHex(parts[2]), peerId)

  without provKey =? makeProviderKey(peerId), err:
    return failure(err.msg)

  trace "Removing provider record", key = provKey
  return (await self.store.delete(provKey))

proc remove*(
  self: ProvidersManager,
  cid: NodeId,
  peerId: PeerId): Future[?!void] {.async.} =

  if cid in self.providers:
    var addCache = self.providers.get(cid).get
    addCache.del(peerId)

  without cidKey =? makeCidKey(cid, peerId), err:
    trace "Error creating key from content id", err = err.msg
    return failure err.msg

  return (await self.store.delete(cidKey))

func new*(
  T: type ProvidersManager,
  store: Datastore,
  disableCache = false,
  ttl = DefaultProviderTTL,
  maxItems = MaxProvidersEntries,
  maxProviders = MaxProvidersPerEntry): T =

  var
    self = T(
      store: store,
      ttl: ttl,
      maxItems: maxItems,
      maxProviders: maxProviders,
      disableCache: disableCache)

  if not disableCache:
    self.providers = ItemsCache.init(maxItems.int)

  self
