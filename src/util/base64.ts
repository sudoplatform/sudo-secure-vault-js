/**
 * Utility class for Base64 encoding and decoding.
 */
export class Base64 {
  static decode(encoded: string): ArrayBuffer {
    return Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))
  }

  static encode(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
  }
}
