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
      if (key, data) =? (await item) and key.isSome:
        let
          expired = Moment.init(uint64.fromBytesBE(data).int64, Microsecond)

        if now >= expired:
          trace "Found expired record", key
          keys.add(key.get)
          without pairs =? key.get.fromCidKey(), err:
            trace "Error extracting parts from cid key", key
            continue

        if keys.len >= batchSize:
          break

    if err =? (await store.delete(keys)).errorOption:
      trace "Error cleaning up batch, records left intact!", size = keys.len, err = err.msg

    trace "Cleaned up expired records", size = keys.len

proc cleanupOrphaned*(
    store: Datastore,
    batchSize = ExpiredCleanupBatch
) {.async.} =
  trace "Cleaning up orphaned records"

  let
    providersQuery = Query.init(ProvidersKey, limit = batchSize, value = false)

  block:
    without iter =? (await store.query(providersQuery)), err:
      trace "Unable to obtain record for key"
      return

    defer:
      if not isNil(iter):
        trace "Cleaning up orphaned query iterator"
        discard (await iter.dispose())

    var count = 0
    for item in iter:
      if count >= batchSize:
        trace "Batch cleaned up", size = batchSize

      count.inc
      if (key, _) =? (await item) and key.isSome:
        without peerId =? key.get.fromProvKey(), err:
          trace "Error extracting parts from cid key", key = key.get
          continue

        without cidKey =? (CidKey / "*" / $peerId), err:
          trace "Error building cid key", err = err.msg
          continue

        without cidIter =? (await store.query(Query.init(cidKey, limit = 1, value = false))), err:
          trace "Error querying key", cidKey, err = err.msg
          continue

        let
          res = block:
            var count = 0
            for item in cidIter:
              if (key, _) =? (await item) and key.isSome:
                count.inc
            count

        if not isNil(cidIter):
          trace "Disposing cid iter"
          discard (await cidIter.dispose())

        if res > 0:
          trace "Peer not orphaned, skipping", peerId
          continue

        if err =? (await store.delete(key.get)).errorOption:
          trace "Error deleting orphaned peer", err = err.msg
          continue

        trace "Cleaned up orphaned peer", peerId
