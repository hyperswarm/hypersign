'use strict'
const assert = require('assert')
const {
  crypto_sign_keypair: createKeypair,
  crypto_sign_detached: sign,
  crypto_generichash: hash,
  crypto_sign_PUBLICKEYBYTES: pkSize,
  crypto_sign_SECRETKEYBYTES: skSize,
  crypto_sign_BYTES: signSize,
  randombytes_buf: randomBytes
} = require('sodium-universal')
const uint64be = require('uint64be')
const bencode = require('bencode')

// VALUE_MAX_SIZE + packet overhead (i.e. the key etc.)
// should be less than the network MTU, normally 1400 bytes
const VALUE_MAX_SIZE = 1000

class Hypersign {
  salt (str = null, size = 32) {
    if (typeof str === 'number') {
      size = str
      str = null
    }
    assert(
      size >= 16 && size <= 64,
      'salt size must be between 16 and 64 bytes (inclusive)'
    )
    const salt = Buffer.alloc(size)
    if (typeof str === 'string') hash(salt, Buffer.from(str))
    else randomBytes(salt)
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
    assert(value.length <= VALUE_MAX_SIZE, `Value size must be <= ${VALUE_MAX_SIZE}`)
    const { keypair } = opts
    assert(keypair, 'keypair is required')
    const { secretKey, publicKey } = keypair
    assert(Buffer.isBuffer(secretKey), 'keypair.secretKey is required')
    assert(Buffer.isBuffer(publicKey), 'keypair.publicKey is required')
    const msg = this.signable(value, opts)
    const signature = Buffer.alloc(signSize)
    sign(signature, msg, secretKey)
    return signature
  }

  signable (value, opts = {}) {
    const { salt = Buffer.alloc(0), seq = 0, encoding = '' } = opts
    assert(Buffer.isBuffer(value), 'Value must be a buffer')
    assert(value.length <= VALUE_MAX_SIZE, `Value size must be <= ${VALUE_MAX_SIZE}`)
    if (salt.length > 0) {
      assert(Buffer.isBuffer(salt), 'salt must be a buffer')
      assert(
        salt.length <= 64,
        'salt size must be no greater than 64 bytes'
      )
    }
    if (encoding === 'bencode') {
      return bencode.encode({ seq, v: value, salt }).slice(1, -1)
    }
    return Buffer.concat([
      uint64be.encode(seq),
      Buffer.from([salt.length]),
      salt,
      value
    ])
  }
}

module.exports = () => new Hypersign()
module.exports.Hypersign = Hypersign
module.exports.VALUE_MAX_SIZE = VALUE_MAX_SIZE
