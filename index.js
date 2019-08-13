'use strict'
const assert = require('assert')
const {
  crypto_sign_keypair: createKeypair,
  crypto_sign_detached: sign,
  crypto_sign_PUBLICKEYBYTES: pkSize,
  crypto_sign_SECRETKEYBYTES: skSize,
  crypto_sign_BYTES: signSize,
  randombytes_buf: randomBytes
} = require('sodium-universal')

// PUT_VALUE_MAX_SIZE + packet overhead (i.e. the key etc.)
// should be less than the network MTU, normally 1400 bytes
const MAX_VALUE_SIZE = 1000

class Hypersign {
  salt (size = 32) {
    assert(
      size >= 16 && size <= 64,
      'salt size must be between 16 and 64 bytes (inclusive)'
    )
    const salt = Buffer.alloc(size)
    randomBytes(salt)
    return salt
  }

  keypair () {
    const publicKey = Buffer.alloc(pkSize)
    const secretKey = Buffer.alloc(skSize)
    createKeypair(publicKey, secretKey)
    return { publicKey, secretKey }
  }

  sign (value, opts) {
    assert(typeof opts === 'object', 'Options are required')
    assert(Buffer.isBuffer(value), 'Value must be a buffer')
    assert(value.length <= MAX_VALUE_SIZE, `Value size must be <= ${MAX_VALUE_SIZE}`)
    const { keypair } = opts
    assert(keypair, 'keypair is required')
    const { secretKey, publicKey } = keypair
    assert(Buffer.isBuffer(secretKey), 'keypair.secretKey is required')
    assert(Buffer.isBuffer(publicKey), 'keypair.publicKey is required')
    const msg = this.signable(value, opts)
    const sig = Buffer.alloc(signSize)
    sign(sig, msg, secretKey)
    return sig
  }

  signable (value, opts = {}) {
    const { salt } = opts
    assert(Buffer.isBuffer(value), 'Value must be a buffer')
    assert(value.length <= MAX_VALUE_SIZE, `Value size must be <= ${MAX_VALUE_SIZE}`)
    if (!salt) return value
    assert(Buffer.isBuffer(salt), 'salt must be a buffer')
    assert(
      salt.length >= 16 && salt.length <= 64,
      'salt size must be between 16 and 64 bytes (inclusive)'
    )
    return Buffer.concat([Buffer.from([salt.length]), salt, value])
  }
}

module.exports = () => new Hypersign()
module.exports.Hypersign = Hypersign
module.exports.MAX_VALUE_SIZE = MAX_VALUE_SIZE
