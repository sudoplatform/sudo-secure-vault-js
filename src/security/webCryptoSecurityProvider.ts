import { SecurityProvider } from '../security/securityProvider'

export class WebCryptoSecurityProvider implements SecurityProvider {
  private static readonly Constants = {
    pbkdfAlgorithm: 'PBKDF2',
    hashingAlgorithm: 'SHA-256',
    saltSize: 32,
    encryptionKeySize: 256,
    encryptionAlgorithm: 'AES-CBC',
    encryptionAlgorithmSpecifier: 'AES/CBC/PKCS7Padding',
    ivSize: 16,
  }

  private async generateSecretKeyBits(
    key: ArrayBuffer,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    rounds: number,
  ): Promise<ArrayBuffer> {
    // Stretch the key using PBKDF2. Only 1 round is neccessary since the input
    // key is assumed to be randomly generated.
    const keyBits = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: WebCryptoSecurityProvider.Constants.pbkdfAlgorithm,
          salt: salt,
          iterations: 1,
          hash: WebCryptoSecurityProvider.Constants.hashingAlgorithm,
        },
        await crypto.subtle.importKey('raw', key, 'PBKDF2', false, [
          'deriveBits',
          'deriveKey',
        ]),
        WebCryptoSecurityProvider.Constants.encryptionKeySize,
      ),
    )

    // Stretch the password using PBKDF2 using the specified rounds.
    const passwordBits = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: WebCryptoSecurityProvider.Constants.pbkdfAlgorithm,
          salt: salt,
          iterations: rounds,
          hash: WebCryptoSecurityProvider.Constants.hashingAlgorithm,
        },
        await crypto.subtle.importKey('raw', password, 'PBKDF2', false, [
          'deriveBits',
          'deriveKey',
        ]),
        WebCryptoSecurityProvider.Constants.encryptionKeySize,
      ),
    )

    // XOR the two key parts to form the secret key used for authentication
    // or encryption.
    const keyLength = keyBits.byteLength
    const buffer = new ArrayBuffer(keyLength)
    const secretKeyBits = new Uint8Array(buffer)
    for (let i = 0; i < keyLength; i++) {
      secretKeyBits[i] = keyBits[i] ^ passwordBits[i]
    }

    return buffer
  }

  public async generateAuthenticationSecret(
    key: ArrayBuffer,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    rounds: number,
  ): Promise<ArrayBuffer> {
    return await this.generateSecretKeyBits(key, password, salt, rounds)
  }

  public async encrypt(
    key: ArrayBuffer,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    rounds: number,
    data: ArrayBuffer,
  ): Promise<{ encrypted: ArrayBuffer; iv: ArrayBuffer }> {
    // Generate the encryption key.
    const secretKeyBits = await this.generateSecretKeyBits(
      key,
      password,
      salt,
      rounds,
    )

    const secretKey = await crypto.subtle.importKey(
      'raw',
      secretKeyBits,
      WebCryptoSecurityProvider.Constants.encryptionAlgorithm,
      false,
      ['encrypt', 'decrypt'],
    )

    const iv = this.generateRandomData(
      WebCryptoSecurityProvider.Constants.ivSize,
    )
    const encrypted = await crypto.subtle.encrypt(
      {
        name: WebCryptoSecurityProvider.Constants.encryptionAlgorithm,
        iv,
      },
      secretKey,
      data,
    )

    new Uint8Array(secretKeyBits).fill(0)

    return { encrypted, iv }
  }

  public async decrypt(
    key: ArrayBuffer,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    rounds: number,
    iv: ArrayBuffer,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    // Generate the encryption key.
    const secretKeyBits = await this.generateSecretKeyBits(
      key,
      password,
      salt,
      rounds,
    )

    const secretKey = await crypto.subtle.importKey(
      'raw',
      secretKeyBits,
      WebCryptoSecurityProvider.Constants.encryptionAlgorithm,
      false,
      ['encrypt', 'decrypt'],
    )

    const decrypted = await crypto.subtle.decrypt(
      {
        name: WebCryptoSecurityProvider.Constants.encryptionAlgorithm,
        iv,
      },
      secretKey,
      data,
    )

    new Uint8Array(secretKeyBits).fill(0)

    return decrypted
  }

  public generateRandomData(size: number): ArrayBuffer {
    const buffer = new ArrayBuffer(size)
    crypto.getRandomValues(new Uint8Array(buffer))
    return buffer
  }

  public generateKeyDerivationSalt(): ArrayBuffer {
    return this.generateRandomData(WebCryptoSecurityProvider.Constants.saltSize)
  }

  public getEncryptionAlgorithmSpecifier(): string {
    return WebCryptoSecurityProvider.Constants.encryptionAlgorithmSpecifier
  }

  getIVLength(): number {
    return WebCryptoSecurityProvider.Constants.ivSize
  }
}
