# codex-dht - Codex DHT
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import std/options
import std/sequtils

import pkg/chronos
import pkg/libp2p
import pkg/datastore
import pkg/chronicles
import pkg/questionable
import pkg/questionable/results

import ./common

const
  ExpiredCleanupBatch* = 1000
  CleanupInterval* = 5.minutes

proc cleanupExpired*(
  store: Datastore,
  batchSize = ExpiredCleanupBatch) {.async.} =
  trace "Cleaning up expired records"

  let
    now = Moment.now()

  let
    q = Query.init(CidKey, limit = batchSize)

  block:
    without iter =? (await store.query(q)), err:
      trace "Unable to obtain record for key", err = err.msg
      return

    defer:
      if not isNil(iter):
        trace "Cleaning up query iterator"
        discard (await iter.dispose())

    var
      keys = newSeq[Key]()

    for item in iter:
      if pair =? (await item) and pair.key.isSome:
        let
          (key, data) = (pair.key.get(), pair.data)
          expired = Moment.init(uint64.fromBytesBE(data).int64, Microsecond)

        if now >= expired:
          trace "Found expired record", key
          keys.add(key)
          without pairs =? key.fromCidKey(), err:
            trace "Error extracting parts from cid key", key
            continue

        if keys.len >= batchSize:
          break

    if err =? (await store.delete(keys)).errorOption:
      trace "Error cleaning up batch, records left intact!", size = keys.len, err = err.msg

    trace "Cleaned up expired records", size = keys.len

proc cleanupOrphaned*(
  store: Datastore,
  batchSize = ExpiredCleanupBatch) {.async.} =
  trace "Cleaning up orphaned records"

  let
    providersQuery = Query.init(ProvidersKey, limit = batchSize)

  block:
    without iter =? (await store.query(providersQuery)), err:
      trace "Unable to obtain record for key"
      return

    defer:
      if not isNil(iter):
        trace "Cleaning up query iterator"
        discard (await iter.dispose())

    var count = 0
    for item in iter:
      if count >= batchSize:
        trace "Batch cleaned up", size = batchSize

      count.inc
      if pair =? (await item) and pair.key.isSome:
        let
          key = pair.key.get()

        without peerId =? key.fromProvKey(), err:
          trace "Error extracting parts from cid key", key
          continue

        without cidKey =? (CidKey / "*" / $peerId), err:
          trace "Error building cid key", err = err.msg
          continue

        without cidIter =? (await store.query(Query.init(cidKey, limit = 1))), err:
          trace "Error querying key", cidKey
          continue

        let
          res = (await allFinished(toSeq(cidIter)))
            .filterIt( it.completed )
            .mapIt( it.read.get )
            .filterIt( it.key.isSome ).len

        if not isNil(cidIter):
          trace "Disposing cid iter"
          discard (await cidIter.dispose())

        if res > 0:
          trace "Peer not orphaned, skipping", peerId
          continue

        if err =? (await store.delete(key)).errorOption:
          trace "Error deleting orphaned peer", err = err.msg
          continue

        trace "Cleaned up orphaned peer", peerId
