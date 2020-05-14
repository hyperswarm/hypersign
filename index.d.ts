declare function _exports(): Hypersign;
export default _exports;
export { Hypersign }
/** VALUE_MAX_SIZE + packet overhead (i.e. the key etc.) should be less than the network MTU, normally 1400 bytes */
export const VALUE_MAX_SIZE: number;

export declare interface KeyPair {
  publicKey:Buffer
  secretKey:Buffer
}

declare interface SignOptions {
  keypair?: KeyPair
  salt?:Buffer
  seq?:number
}

declare class Hypersign {
  /** Utility method for creating a random or hashed salt value. If called with a string the string will be hashed, to a generic hash of size length. If called without any inputs, or with a number, random býtes of size length will be returned */
  salt(str?: string, size?: number): Buffer;
  /** Use this method to generate an assymetric keypair. Returns an object with {publicKey, secretKey}. publicKey holds a public key buffer, secretKey holds a private key buffer. */
  keypair(): KeyPair
  /** Utility method which can be used to create a signature using the crypto_sign_detached Sodium method. This only needs to be used when you do not need to apply encoding to value, salt and seq(e.g. if value and options have already been passed to signable). */
  cryptoSign(msg: Buffer, keypair: KeyPair ): Buffer;
  /** Utility method which can be used to create a signature. */
  sign(value: Buffer, opts: SignOptions): Buffer;
  /** Utility method which returns the exact buffer that would be signed in by sign. This is only needed when using a salt, otherwise it will return the same value passed in. */
  signable(value: Buffer, opts?: { salt?:Buffer, seq?:number }): Buffer;
}
