import
  std/sugar,
  libp2p/crypto/[crypto, secp]

from secp256k1 import ecdh, SkEcdhSecretSize, toRaw, SkSecretKey, SkPublicKey

type
  SharedSecret* = object
    ## Representation of ECDH shared secret, without leading `y` byte
    data*: array[SkEcdhSecretSize, byte]

proc fromHex*(T: type PrivateKey, data: string): Result[PrivateKey, cstring] =
  let skKey = ? SkPrivateKey.init(data).mapErr(e =>
                ("Failed to init private key from hex string: " & $e).cstring)
  ok PrivateKey.init(skKey)

proc fromHex*(T: type PublicKey, data: string): Result[PublicKey, cstring] =
  let skKey = ? SkPublicKey.init(data).mapErr(e =>
                ("Failed to init public key from hex string: " & $e).cstring)
  ok PublicKey.init(skKey)

proc ecdhSharedSecretHash(output: ptr byte, x32, y32: ptr byte, data: pointer): cint
                    {.cdecl, raises: [].} =
  ## Hash function used by `ecdhSharedSecret` below
  # `x32` and `y32` are result of scalar multiplication of publicKey * privateKey.
  # Both `x32` and `y32` are 32 bytes length.
  # Take the `x32` part as ecdh shared secret.

  # output length is derived from x32 length and taken from ecdh
  # generic parameter `KeyLength`
  copyMem(output, x32, SkEcdhSecretSize)
  return 1

func ecdhSharedSecret(seckey: SkPrivateKey, pubkey: secp.SkPublicKey): SharedSecret =
  ## Compute ecdh agreed shared secret.
  let res = ecdh[SkEcdhSecretSize](SkSecretKey(seckey), secp256k1.SkPublicKey(pubkey), ecdhSharedSecretHash, nil)
  # This function only fail if the hash function return zero.
  # Because our hash function always success, we can turn the error into defect
  doAssert res.isOk, $res.error
  SharedSecret(data: res.get)

proc ecdhRaw*(
    priv: PrivateKey,
    pub: PublicKey): Result[SharedSecret, cstring] =

  # TODO: Do we need to support non-secp256k1 schemes?
  if priv.scheme != Secp256k1 or pub.scheme != Secp256k1:
    return err "Must use secp256k1 scheme".cstring

  ok ecdhSharedSecret(priv.skkey, pub.skkey)

proc toRaw*(pubkey: PublicKey): seq[byte] =
  secp256k1.SkPublicKey(pubkey.skkey).toRaw()[1..^1]
