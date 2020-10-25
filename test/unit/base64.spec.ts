import { Base64 } from '../../src/util/base64'

describe('Base64', () => {
  it('Base 64 encode and decode.', () => {
    const encoded = Base64.encode(Buffer.from('dummy_data', 'utf8'))
    const decoded = Base64.decode(encoded)
    expect(Buffer.from(decoded).toString('utf8')).toBe('dummy_data')
  })
})
