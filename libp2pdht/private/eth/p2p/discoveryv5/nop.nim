#
#
#                    NimCrypto
#        (c) Copyright 2023 Status
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements a no-op(NOP) crypto that des nothing,
## Do not use for anything else than testing.

{.deadCodeElim:on.}

when sizeof(int) == 4:
  type
    NopContext[bits: static[uint]] = object
      skey: array[120, uint32]
      nr: int
elif sizeof(int) == 8:
  type
    NopContext[bits: static[uint]] = object
      skey: array[120, uint64]
      nr: int

type
  nop128* = NopContext[128]
  nop192* = NopContext[192]
  nop256* = NopContext[256]
  nop* = nop128 | nop192 | nop256

proc encrypt*(ctx: NopContext, input: openarray[byte],
              output: var openarray[byte]) =
  for i, v in input:
    output[i] = v

proc decrypt*(ctx: NopContext, input: openarray[byte],
              output: var openarray[byte]) =
  for i, v in input:
    output[i] = v

template sizeKey*(ctx: NopContext): int =
  (ctx.bits div 8)

template sizeBlock*(ctx: NopContext): int =
  (16)

template sizeKey*(r: typedesc[nop]): int =
  when r is nop128:
    (16)
  elif r is nop192:
    (24)
  elif r is nop256:
    (32)

template sizeBlock*(r: typedesc[nop]): int =
  (16)

proc init*(ctx: var NopContext, key: openarray[byte]) {.inline.} =
  discard

proc init*(ctx: var NopContext, key: ptr byte, nkey: int = 0) {.inline.} =
  discard

proc clear*(ctx: var NopContext) {.inline.} =
  discard

proc encrypt*(ctx: var NopContext, inbytes: ptr byte,
              outbytes: ptr byte) {.inline.} =
  outbytes = inbytes

proc decrypt*(ctx: var NopContext, inbytes: ptr byte,
              outbytes: ptr byte) {.inline.} =
  outbytes = inbytes
