'use strict'
const { test } = require('tap')
const {
  crypto_sign_verify_detached: verify,
  crypto_generichash: hash
} = require('sodium-universal')
const hypersign = require('../')()
const bencode = require('bencode')
test('keypair', async ({ is }) => {
  const { publicKey, secretKey } = hypersign.keypair()
  is(publicKey instanceof Buffer, true)
  is(publicKey.length, 32)
  is(secretKey instanceof Buffer, true)
  is(secretKey.length, 64)
})

test('salt', async ({ is, throws }) => {
  const salt = hypersign.salt()
  is(salt instanceof Buffer, true)
  is(salt.length, 32)
  is(hypersign.salt(64).length, 64)
  throws(() => hypersign.salt(15))
  throws(() => hypersign.salt(65))
})

test('salt string', async ({ is, throws }) => {
  const salt = hypersign.salt('test')
  is(salt instanceof Buffer, true)
  is(salt.length, 32)
  is(hypersign.salt(64).length, 64)
  const check = Buffer.alloc(32)
  hash(check, Buffer.from('test'))
  is(salt.equals(check), true)
  throws(() => hypersign.salt('test', 15))
  throws(() => hypersign.salt('test', 65))
})

test('signable', async ({ is, same }) => {
  const salt = hypersign.salt()
  const value = Buffer.from('test')
  same(
    hypersign.signable(value),
    Buffer.concat([
      Buffer.alloc(9),
      value
    ])
  )
  same(
    hypersign.signable(value, { seq: 1 }),
    Buffer.concat([
      Buffer.concat([Buffer.alloc(7), Buffer.alloc(1, 1)]),
      Buffer.alloc(1),
      value
    ])
  )
  same(
    hypersign.signable(value, { salt }),
    Buffer.concat([
      Buffer.concat([Buffer.alloc(7), Buffer.alloc(1)]),
      Buffer.from([salt.length]),
      salt,
      value
    ])
  )
})

test('signable bencode encoding', async ({ is, same }) => {
  const salt = hypersign.salt()
  const value = Buffer.from('test')
  same(
    hypersign.signable(value, { encoding: 'bencode' }),
    bencode.encode({ seq: 0, v: value, salt: Buffer.alloc(0) }).slice(1, -1)
  )
  same(
    hypersign.signable(value, { seq: 1, encoding: 'bencode' }),
    bencode.encode({ seq: 1, v: value, salt: Buffer.alloc(0) }).slice(1, -1)
  )
  same(
    hypersign.signable(value, { salt, encoding: 'bencode' }),
    bencode.encode({ seq: 0, v: value, salt }).slice(1, -1)
  )
})

test('mutable signable - salt must be a buffer', async ({ throws }) => {
  throws(() => hypersign.signable(Buffer.from('test'), { salt: 'no' }), 'salt must be a buffer')
})

test('mutable signable - salt size must be no greater than 64 bytes', async ({ throws }) => {
  throws(
    () => hypersign.signable(Buffer.from('test'), { salt: Buffer.alloc(65) }),
    'salt size must be no greater than 64 bytes'
  )
})

test('mutable signable - value must be buffer', async ({ throws }) => {
  const keypair = hypersign.keypair()
  throws(() => hypersign.signable('test', { keypair }), 'Value must be a buffer')
})

test('mutable signable - value size must be <= 1000 bytes', async ({ throws }) => {
  const keypair = hypersign.keypair()
  throws(
    () => hypersign.signable(Buffer.alloc(1001), { keypair }),
    'Value size must be <= 1000'
  )
})

test('sign', async ({ is }) => {
  const keypair = hypersign.keypair()
  const { publicKey } = keypair
  const salt = hypersign.salt()
  const value = Buffer.from('test')
  is(
    verify(
      hypersign.sign(value, { keypair }),
      hypersign.signable(value),
      publicKey
    ),
    true
  )
  is(
    verify(
      hypersign.sign(value, { salt, keypair }),
      hypersign.signable(value, { salt }),
      publicKey
    ),
    true
  )
  is(
    verify(
      hypersign.sign(value, { seq: 2, keypair }),
      hypersign.signable(value, { seq: 2 }),
      publicKey
    ),
    true
  )
})

test('sign - bencode encoding', async ({ is }) => {
  const keypair = hypersign.keypair()
  const { publicKey } = keypair
  const salt = hypersign.salt()
  const value = Buffer.from('test')
  const encoding = 'bencode'
  is(
    verify(
      hypersign.sign(value, { keypair, encoding }),
      hypersign.signable(value, { encoding }),
      publicKey
    ),
    true
  )
  is(
    verify(
      hypersign.sign(value, { salt, keypair, encoding }),
      hypersign.signable(value, { salt, encoding }),
      publicKey
    ),
    true
  )
  is(
    verify(
      hypersign.sign(value, { seq: 2, keypair, encoding }),
      hypersign.signable(value, { seq: 2, encoding }),
      publicKey
    ),
    true
  )
})

test('mutable sign - salt must be a buffer', async ({ throws }) => {
  throws(() => hypersign.sign(Buffer.from('test'), { salt: 'no' }), 'salt must be a buffer')
})

test('mutable sign - salt size must be >= 16 bytes and <= 64 bytes', async ({ throws }) => {
  throws(
    () => hypersign.sign(Buffer.from('test'), { salt: Buffer.alloc(15) }),
    'salt size must be between 16 and 64 bytes (inclusive)'
  )
  throws(
    () => hypersign.sign(Buffer.from('test'), { salt: Buffer.alloc(65) }),
    'salt size must be between 16 and 64 bytes (inclusive)'
  )
})

test('mutable sign - value must be buffer', async ({ throws }) => {
  const keypair = hypersign.keypair()
  throws(() => hypersign.sign('test', { keypair }), 'Value must be a buffer')
})

test('mutable sign - options are required', async ({ throws }) => {
  throws(() => hypersign.sign('test'), 'Options are required')
})

test('mutable sign - value size must be <= 1000 bytes', async ({ throws }) => {
  const keypair = hypersign.keypair()
  throws(
    () => hypersign.sign(Buffer.alloc(1001), { keypair }),
    'Value size must be <= 1000'
  )
})

test('mutable sign - keypair option is required', async ({ throws }) => {
  throws(
    () => hypersign.sign(Buffer.alloc(1001), {}),
    'keypair is required'
  )
})

test('mutable sign - keypair must have secretKey which must be a buffer', async ({ throws }) => {
  const keypair = hypersign.keypair()
  keypair.secretKey = 'nope'
  throws(
    () => hypersign.sign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
  delete keypair.secretKey
  throws(
    () => hypersign.sign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
})
