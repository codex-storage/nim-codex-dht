import
  std/sugar,
  libp2p/crypto/[crypto, secp],
  stew/[byteutils, objects, results, ptrops]

# from secp256k1 import ecdh, SkEcdhSecretSize, toRaw, SkSecretKey, SkPublicKey
import secp256k1

const
  KeyLength* = SkEcdhSecretSize
    ## Ecdh shared secret key length without leading byte
    ## (publicKey * privateKey).x, where length of x is 32 bytes

  FullKeyLength* = KeyLength + 1
    ## Ecdh shared secret with leading byte 0x02 or 0x03

type
  SharedSecret* = object
    ## Representation of ECDH shared secret, without leading `y` byte
    data*: array[KeyLength, byte]
  
  SharedSecretFull* = object
    ## Representation of ECDH shared secret, with leading `y` byte
    ## (`y` is 0x02 when (publicKey * privateKey).y is even or 0x03 when odd)
    data*: array[FullKeyLength, byte]

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
  ## 
  ## `x32` and `y32` are result of scalar multiplication of publicKey * privateKey.
  ## Both `x32` and `y32` are 32 bytes length.
  ## 
  ## Take the `x32` part as ecdh shared secret.
  ## output length is derived from x32 length and taken from ecdh
  ## generic parameter `KeyLength`
  copyMem(output, x32, SkEcdhSecretSize)
  return 1

func ecdhSharedSecret(seckey: SkPrivateKey, pubkey: secp.SkPublicKey): SharedSecret =
  ## Compute ecdh agreed shared secret.
  let res = ecdh[SkEcdhSecretSize](secp256k1.SkSecretKey(seckey),
                                   secp256k1.SkPublicKey(pubkey),
                                   ecdhSharedSecretHash, nil)
  # This function only fail if the hash function return zero.
  # Because our hash function always success, we can turn the error into defect
  doAssert res.isOk, $res.error
  SharedSecret(data: res.get)

proc toRaw*(pubkey: PublicKey): seq[byte] =
  secp256k1.SkPublicKey(pubkey.skkey).toRaw()[1..^1]

proc ecdhSharedSecretFullHash(output: ptr byte, x32, y32: ptr byte, data: pointer): cint
                    {.cdecl, raises: [].} =
  ## Hash function used by `ecdhSharedSecretFull` below
  # `x32` and `y32` are result of scalar multiplication of publicKey * privateKey.
  # Leading byte is 0x02 if `y32` is even and 0x03 if odd. Then concat with `x32`.

  # output length is derived from `x32` length + 1 and taken from ecdh
  # generic parameter `FullKeyLength`

  # output[0] = 0x02 | (y32[31] & 1)
  output[] = 0x02 or (y32.offset(31)[] and 0x01)
  copyMem(output.offset(1), x32, KeyLength)
  return 1

func ecdhSharedSecretFull*(seckey: PrivateKey, pubkey: PublicKey): SharedSecretFull =
  ## Compute ecdh agreed shared secret with leading byte.
  ## 
  let res = ecdh[FullKeyLength](secp256k1.SkSecretKey(seckey.skkey),
                                secp256k1.SkPublicKey(pubkey.skkey),
                                ecdhSharedSecretFullHash, nil)
  # This function only fail if the hash function return zero.
  # Because our hash function always success, we can turn the error into defect
  doAssert res.isOk, $res.error
  SharedSecretFull(data: res.get)

proc ecdhRaw*(
    priv: PrivateKey,
    pub: PublicKey
): Result[SharedSecret, cstring] =
  ## emulate old ecdhRaw style keys
  ## 
  ## this includes a leading 0x02 or 0x03
  ## 
  # TODO: Do we need to support non-secp256k1 schemes?
  if priv.scheme != Secp256k1 or pub.scheme != Secp256k1:
    return err "Must use secp256k1 scheme".cstring

  ok ecdhSharedSecret(priv.skkey, pub.skkey)
