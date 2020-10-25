import { WebCryptoSecurityProvider } from '../../src/security/webCryptoSecurityProvider'
global.crypto = require('isomorphic-webcrypto')

describe('WebCryptoSecurityProvider', () => {
  const provider = new WebCryptoSecurityProvider()
  it('Generate random data.', () => {
    const data1 = provider.generateRandomData(10)
    const data2 = provider.generateRandomData(10)
    const data3 = provider.generateRandomData(20)
    expect(data1.byteLength).toBe(10)
    expect(data2.byteLength).toBe(10)
    expect(data3.byteLength).toBe(20)
    expect(Buffer.from(data1).toString('hex')).not.toBe(
      Buffer.from(data2).toString('hex'),
    )
  })

  it('Encrypt and decrypt.', async () => {
    const key = provider.generateRandomData(16)
    const salt = provider.generateKeyDerivationSalt()
    const password = Buffer.from('dummy_password', 'utf8')
    const data = Buffer.from('dummy_data', 'utf8')
    const { encrypted, iv } = await provider.encrypt(
      key,
      password,
      salt,
      100,
      data,
    )

    let decrypted = await provider.decrypt(
      key,
      password,
      salt,
      100,
      iv,
      encrypted,
    )

    expect(Buffer.from(decrypted).toString('utf8')).toBe('dummy_data')

    // Bad salt.
    try {
      decrypted = await provider.decrypt(
        key,
        password,
        provider.generateRandomData(16),
        100,
        iv,
        encrypted,
      )
      fail('Expected error not thrown.')
    } catch (error) {
      // Expected error thrown.
    }

    // Bad key.
    try {
      decrypted = await provider.decrypt(
        key,
        provider.generateRandomData(16),
        salt,
        100,
        iv,
        encrypted,
      )
      fail('Expected error not thrown.')
    } catch (error) {
      // Expected error thrown.
    }

    // Bad password.
    try {
      decrypted = await provider.decrypt(
        key,
        Buffer.from('bad_password', 'utf8'),
        salt,
        100,
        iv,
        encrypted,
      )
      fail('Expected error not thrown.')
    } catch (error) {
      // Expected error thrown.
    }

    // Bad rounds.
    try {
      decrypted = await provider.decrypt(key, password, salt, 99, iv, encrypted)
      fail('Expected error not thrown.')
    } catch (error) {
      // Expected error thrown.
    }

    // Bad iv.
    try {
      decrypted = await provider.decrypt(
        key,
        password,
        salt,
        100,
        provider.generateRandomData(16),
        encrypted,
      )
      fail('Expected error not thrown.')
    } catch (error) {
      // Expected error thrown.
    }
  })
})
