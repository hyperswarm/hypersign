# @hyperswarm/hypersign

Utility methods related to public key cryptography to be used with distributed mutable storage.

```
npm install @hyperswarm/hypersign
```

## API

#### `const { keypair, salt, sign, signable } = hypersign()`

Call the exported function to get hypersign instance.

There is also a class `hypersign.HyperSign` which can be
extended.

#### `keypair()`

Use this method to generate an assymetric keypair.
Returns an object with `{publicKey, secretKey}`. `publicKey` holds a public key buffer, `secretKey` holds a private key buffer.

#### `salt(size = 32)`

Utility method for creating a random salt value.

#### `sign(value, options)`

Utility method which can be used to create a `sig`.

Options:

* `keypair` – REQUIRED, use `keypair` to generate this.
* `salt` - OPTIONAL - default `undefined`, a buffer >= 16 and <= 64 bytes. If supplied it will salt the signature used to verify mutable values.

#### `signable(value, options)`

Utility method which returns the exact buffer that would be signed in by `sign`. This is only needed when using a salt, otherwise it will return the same `value` passed in. This method is to facilitate out-of-band signing (e.g. hardware signing), do not pass the returned signable value into `sign`, it already uses `signable`.

Options:

* `salt` - OPTIONAL - default `undefined`, a buffer >= 16 and <= 64 bytes. If supplied it will salt the signature used to verify mutable values.

## License

MIT
