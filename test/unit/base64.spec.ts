import { Base64 } from '../../src/util/base64'
global.crypto = require('isomorphic-webcrypto')

describe('Base64', () => {
  it('Base 64 encode and decode.', () => {
    const encoded = Base64.encode(Buffer.from('dummy_data', 'utf8'))
    const decoded = Base64.decode(encoded)
    expect(Buffer.from(decoded).toString('utf8')).toBe('dummy_data')
  })

  it('Base 64 encode and decode large blob.', () => {
    const ba = new Uint8Array(500000)
    crypto.getRandomValues(ba)
    const encoded = Base64.encode(ba)
    const decoded = Base64.decode(encoded)
    expect(decoded.byteLength).toBe(ba.byteLength)
    for (let i = 0; i < decoded.byteLength; i++) {
      expect(decoded[i]).toBe(ba[i])
    }
  })
})
