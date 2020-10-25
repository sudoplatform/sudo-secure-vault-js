/**
 * Interface to be implemented by security providers responsible for cryptographic
 * and key management operations.
 */
export interface SecurityProvider {
  /**
   * Generate random data.
   *
   * @param size - Size of the random data to generate.
   *
   * @returns Random data.
   *
   */
  generateRandomData(size: number): ArrayBuffer

  /**
   * Generate salt for key derivation.
   *
   * @returns Salt.
   */
  generateKeyDerivationSalt(): ArrayBuffer

  /**
   * Generate the secret used for authentication.
   *
   * @param key - Key deriving key.
   * @param password - Vault password.
   * @param salt - Key derivation salt.
   * @param rounds - PBKDF rounds.
   *
   * @returns Authentication secret.
   */
  generateAuthenticationSecret(
    key: ArrayBuffer,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    rounds: number,
  ): Promise<ArrayBuffer>

  /**
   * Encrypts the specified data.
   *
   * @param key - Key deriving key.
   * @param password - Vault password.
   * @param salt - Key derivation salt.
   * @param rounds - PBKDF rounds.
   * @param data - Data to encrypt.
   *
   * @returns Encrypted data and IV.
   *
   */
  encrypt(
    key: ArrayBuffer,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    rounds: number,
    data: ArrayBuffer,
  ): Promise<{ encrypted: ArrayBuffer; iv: ArrayBuffer }>

  /**
   * Retrieve a single vault matching the specified ID.
   *
   * @param key - Key deriving key.
   * @param password - Vault password.
   * @param salt - Key derivation salt.
   * @param rounds - PBKDF rounds.
   * @param iv - IV to use for decryption.
   * @param data - Data to decrypt.
   *
   * @returns Decrypted data.
   *
   */
  decrypt(
    key: ArrayBuffer,
    password: ArrayBuffer,
    salt: ArrayBuffer,
    rounds: number,
    iv: ArrayBuffer,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer>

  /**
   * Returns the encryption algorithm specifier as string.
   *
   * @returns Encryption algorithm specifier.
   */
  getEncryptionAlgorithmSpecifier(): string

  /**
   * Returns the IV length used by this provider for encryption.
   *
   * @return IV length.
   */
  getIVLength(): number
}
