# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# ChronoSim: simulation/emulation wrapper around Chronos

import
  std/[tables, deques, random],
  chronos,
  chronicles

logScope:
  topics = "ChronoSim"

const
  timeWarp = 1
  emulateDatagram = true

# chronos uses SomeIntegerI64. We shoudl be more specific here to override
proc milliseconds*(v: int): Duration {.inline.} =
  chronos.milliseconds(v * timeWarp)

proc seconds*(v: int): Duration {.inline.} =
  chronos.seconds(v * timeWarp)

when(emulateDatagram): #enable network emulator
  type
    DatagramCallback* = proc(transp: DatagramTransport,
                            remote: TransportAddress): Future[void] {.
                        gcsafe, raises: [Defect].}

    DatagramTransport* = ref object
      udata*: pointer                 # User-driven pointer
      local: TransportAddress         # Local address
      callback: DatagramCallback      # Receive data callback
      ingress: Deque[seq[byte]]
      egress: Deque[(TransportAddress, seq[byte])]  # simple FIFO for now

  var network = initTable[Port, DatagramTransport]()

  proc `$`*(transp: DatagramTransport): string =
    $transp.local

  proc recvFrom[T](transp: DatagramTransport, remote: TransportAddress,
              msg: sink seq[T], msglen = -1) =
    trace "recv:",  src = remote, dst = transp.local
    {.gcsafe.}:
      transp.ingress.addLast(msg)
      # call the callback on remote
      asyncCheck transp.callback(transp, remote)

  proc getLatency(src: TransportAddress, dst: TransportAddress) : Duration =
    50.milliseconds

  proc getLoss(src: TransportAddress, dst: TransportAddress) : float =
    0.0
  proc getLineTime(transp: DatagramTransport, msg: seq[byte]) : Duration =
    # let bandwith = transp.bandwidth
    let bandwidth = 100 # Bytes/ms = KB/sec
    (msg.len div bandwidth).milliseconds

  proc sendTo*[T](transp: DatagramTransport, remote: TransportAddress,
              msg: sink seq[T], msglen = -1) {.async.} =
    trace "send:", src = transp.local, dst = remote

    #transp.egress.addLast(remote, msg)
    #await sleepAsync(getLineTime(transp, msg))

    if rand(1.0) < getLoss(transp.local, remote):
      return

    await sleepAsync(getLatency(transp.local, remote))
    {.gcsafe.}:
      network[remote.port].recvFrom(transp.local, msg)

  proc getMessage*(t: DatagramTransport,): seq[byte] {.
      raises: [Defect, CatchableError].} =
    #echo "getMessage "
    t.ingress.popFirst()

  proc close*(transp: DatagramTransport) =
    debug "close"

  proc closed*(transp: DatagramTransport): bool {.inline.} =
    result = false

  proc closeWait*(transp: DatagramTransport) {.async.} =
    debug "closeWait "

  proc getUserData*[T](transp: DatagramTransport): T {.inline.} =
    ## Obtain user data stored in ``transp`` object.
    result = cast[T](transp.udata)

  proc newDatagramTransport*[T](cbproc: DatagramCallback,
                            udata: ref T,
                            local: TransportAddress = AnyAddress,
                            ): DatagramTransport {.
      raises: [Defect, CatchableError].} =
    debug "new"
    result = DatagramTransport()
    GC_ref(udata)
    result.udata = cast[pointer](udata)
    result.local = local
    result.callback = cbproc
    {.gcsafe.}:
      network[local.port] = result

export seconds, milliseconds
export TransportAddress, initTAddress
export async, sleepAsync, complete, await
export Future, FutureBase, newFuture, futureContinue
export TransportOsError