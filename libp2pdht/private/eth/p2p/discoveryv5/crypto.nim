import
  std/sugar,
  libp2p/crypto/[crypto, secp]

from secp256k1 import ecdhRaw, SkEcdhRawSecret, toRaw

proc fromHex*(T: type PrivateKey, data: string): Result[PrivateKey, cstring] =
  let skKey = ? SkPrivateKey.init(data).mapErr(e =>
                ("Failed to init private key from hex string: " & $e).cstring)
  ok PrivateKey.init(skKey)

proc fromHex*(T: type PublicKey, data: string): Result[PublicKey, cstring] =
  let skKey = ? SkPublicKey.init(data).mapErr(e =>
                ("Failed to init public key from hex string: " & $e).cstring)
  ok PublicKey.init(skKey)

func ecdhRaw*(seckey: SkPrivateKey, pubkey: SkPublicKey): SkEcdhRawSecret {.borrow.}

proc ecdhRaw*(
    priv: PrivateKey,
    pub: PublicKey): Result[SkEcdhRawSecret, cstring] =

  # TODO: Do we need to support non-secp256k1 schemes?
  if priv.scheme != Secp256k1 or pub.scheme != Secp256k1:
    return err "Must use secp256k1 scheme".cstring

  ok ecdhRaw(priv.skkey, pub.skkey)

proc toRaw*(pubkey: PublicKey): seq[byte] =
  secp256k1.SkPublicKey(pubkey.skkey).toRaw()[1..^1]
