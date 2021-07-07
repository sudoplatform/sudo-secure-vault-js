/**
 * Utility class for Base64 encoding and decoding.
 */
export class Base64 {
  static decode(encoded: string): ArrayBuffer {
    return Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))
  }

  static encode(buffer: ArrayBuffer): string {
    let encoded = ''
    const bytes = new Uint8Array(buffer)
    const len = bytes.byteLength
    for (let i = 0; i < len; i++) {
      encoded += String.fromCharCode(bytes[i])
    }
    return btoa(encoded)
  }
}
