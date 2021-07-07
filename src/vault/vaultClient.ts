import { InvalidVaultError } from '../global/error'
import {
  NotRegisteredError,
  NotSignedInError,
  NotAuthorizedError,
  InvalidOwnershipProofError,
  VersionMismatchError,
  InsufficientEntitlementsError,
  UnknownGraphQLError,
  ServiceError,
  FatalError,
  UserNotConfirmedError,
  RequestFailedError,
  Logger,
  DefaultLogger,
} from '@sudoplatform/sudo-common'
import { AuthClient } from '../client/authClient'
import { Config } from './config'
import { ApiClient } from '../client/apiClient'
import { Base64 } from '../util/base64'
import { Buffer } from '../util/buffer'
import { SecurityProvider } from '../security/securityProvider'
import { WebCryptoSecurityProvider } from '../security/webCryptoSecurityProvider'
import { SudoUserClient } from '@sudoplatform/sudo-user'
import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import { ApolloLink } from 'apollo-link'

/**
 * Vault owner.
 */
export interface Owner {
  id: string
  issuer: string
}

/**
 * Vault metadata.
 */
export interface VaultMetadata {
  /**
   * Unique ID.
   */
  id: string

  /**
   * Vault owner (User).
   */
  owner: string

  /**
   * Object version.
   */
  version: number

  /**
   * Blob format specifier.
   */
  blobFormat: string

  /**
   * Date/time at which the vault was created.
   */
  createdAt: Date

  /**
   * Date/time at which the vault was last modified.
   */
  updatedAt: Date

  /**
   * List of vault owners.
   */
  owners: Owner[]
}

/**
 * Data required to initialize the client.
 */
export interface InitializationData {
  owner: string
  authenticationSalt: ArrayBuffer
  encryptionSalt: ArrayBuffer
  pbkdfRounds: number
}

/**
 * Vault.
 */
export interface Vault extends VaultMetadata {
  /**
   * Blob stored securely in the vault.
   */
  blob: ArrayBuffer
}

/**
 * Client responsible for interacting with Secure Vault service to manage highly sensitive user
 * data such as login credentials. Most APIs require two-factor authentication, and data is
 * encrypted and decrypted on the client. Before creating a new vault, a new Secure Vault service
 * user must be registered via `register` API. The cryptographic key and the password registered
 * are then required in subsequent API invocations. Note: The sensitive input data such as key
 * and password should be zeroed after using them to call the API provided by this client.
 *
 * @beta
 */
export interface SudoSecureVaultClient {
  /**
   * Registers a new user with Secure Vault service.
   *
   * @param key - Key deriving key. The key size can be 128 - 256 bit.
   * @param password - Vault password.
   *
   * @returns Username of the newly registered user.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link UserNotConfirmedError}
   */
  register(key: ArrayBuffer, password: ArrayBuffer): Promise<string>

  /**
   * Returns the initialization data. If the client has a cached copy
   * then the cached initialization data will be returned otherwise
   * it will be fetched from the backend. This is mainly used for
   * testing and the consuming app is not expected to use this method.
   *
   * @returns Initialization data if one exists.
   *
   * @throws {@link RequestFailedError}
   */
  getInitializationData(): Promise<InitializationData | undefined>

  /**
   * Determines whether or not a Secure Vault user has been
   * registered.
   *
   * @returns `true` if a Secure Vault user has been registered.
   */
  isRegistered(): Promise<boolean>

  /**
   * Creates a new vault.
   *
   * @param key - Key deriving key.
   * @param password - Vault password.
   * @param blob - Blob to encrypt and store.
   * @param blobFormat - Specifier for the format/structure of information represented in the blob.
   * @param ownershipProof - Ownership proof of the Sudo to be associate with the vault. The ownership proof
   *                         must contain audience of "sudoplatform.secure-vault.vault".
   *
   * @returns Newly created vault's metadata.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link InvalidOwnershipProofError}
   * @throws {@link InsufficientEntitlementsError}
   * @throws {@link LimitExceededError}
   * @throws {@link UnknownGraphQLError}
   * @throws {@link RequestFailedError}
   * @throws {@link ServiceError}
   * @throws {@link FatalError}
   */
  createVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    blob: ArrayBuffer,
    blobFormat: string,
    ownershipProof: string,
  ): Promise<VaultMetadata>

  /**
   * Updates an existing vault.
   *
   * @param key - Key deriving key.
   * @param password - Vault password.
   * @param id - ID of the vault to update.
   * @param version - Vault version.
   * @param blob - Blob to encrypt and store.
   * @param blobFormat - Specifier for the format/structure of information represented in the blob.
   *
   * @returns Updated vault's metadata.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link InsufficientEntitlementsError}
   * @throws {@link VersionMismatchError}
   * @throws {@link LimitExceededError}
   * @throws {@link RequestFailedError}
   * @throws {@link UnknownGraphQLError}
   * @throws {@link ServiceError}
   */
  updateVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
    version: number,
    blob: ArrayBuffer,
    blobFormat: string,
  ): Promise<VaultMetadata>

  /**
   * Deletes an existing vault.
   *
   * @param id - ID of the vault to delete.
   *
   * @returns Deleted vault's metadata.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link RequestFailedError}
   * @throws {@link UnknownGraphQLError}
   * @throws {@link ServiceError}
   */
  deleteVault(id: string): Promise<VaultMetadata | undefined>

  /**
   * Retrieve a single vault matching the specified ID.
   *
   * @param key - Key deriving key.
   * @param password - Vault password.
   * @param id - ID of the vault to retrieve.
   *
   * @returns Retrieved vault.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link InsufficientEntitlementsError}
   * @throws {@link InvalidVaultError}
   * @throws {@link RequestFailedError}
   * @throws {@link UnknownGraphQLError}
   * @throws {@link ServiceError}
   */
  getVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
  ): Promise<Vault | undefined>

  /**
   * Retrieves all vaults owned by the authenticated user.
   *
   * @param key - Key deriving key.
   * @param password - Vault password.
   *
   * @returns List containing the vaults retrieved.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link InsufficientEntitlementsError}
   * @throws {@link InvalidVaultError}
   * @throws {@link RequestFailedError}
   * @throws {@link UnknownGraphQLError}
   * @throws {@link ServiceError}
   */
  listVaults(key: ArrayBuffer, password: ArrayBuffer): Promise<Vault[]>

  /**
   * Retrieves metadata for all vaults. This can be used to determine if any vault was
   * updated without requiring the extra authentication and decryption.
   *
   * @returns List containing the metadata of vaults retrieved.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link RequestFailedError}
   * @throws {@link UnknownGraphQLError}
   * @throws {@link ServiceError}
   */
  listVaultsMetadataOnly(): Promise<VaultMetadata[]>

  /**
   * Changes the vault password. Existing vaults will be downloaded, re-encrypted and
   * uploaded so this API may take some time to complete.
   *
   * @param key - Key deriving key.
   * @param oldPassword - Old vault password.
   * @param newPassword - New vault password.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link InsufficientEntitlementsError}
   * @throws {@link InvalidVaultError}
   * @throws {@link VersionMismatchError}
   * @throws {@link UnknownGraphQLError}
   * @throws {@link ServiceError}
   */
  changeVaultPassword(
    key: ArrayBuffer,
    oldPassword: ArrayBuffer,
    newPassword: ArrayBuffer,
  ): Promise<void>

  /**
   * Resets internal state and clear any cached data.
   */
  reset(): void

  /**
   * De-registers the current user from Secure Vault service.
   *
   * @throws {@link NotAuthorizedError}
   * @throws {@link RequestFailedError}
   */
  deregister(): Promise<void>
}

export class DefaultSudoSecureVaultClient implements SudoSecureVaultClient {
  private config: Config
  private authClient: AuthClient
  private apiClient: ApiClient
  private sudoUserClient: SudoUserClient
  private initializationData?: InitializationData
  private securityProvider: SecurityProvider
  private logger: Logger
  private pbkdfRounds: number

  constructor(
    sudoUserClient: SudoUserClient,
    config?: Config,
    authClient?: AuthClient,
    apiClient?: ApiClient,
    securityProvder?: SecurityProvider,
    logger?: Logger,
    link?: ApolloLink,
  ) {
    this.logger = logger ?? new DefaultLogger('SudoSecureVault', 'info')

    this.config =
      config ??
      DefaultConfigurationManager.getInstance().bindConfigSet<Config>(
        Config,
        'secureVaultService',
      )

    this.logger.info('Intializating the client.', { config })

    this.pbkdfRounds = this.config.pbkdfRounds
    this.sudoUserClient = sudoUserClient
    this.securityProvider = securityProvder ?? new WebCryptoSecurityProvider()

    this.authClient =
      authClient ??
      new AuthClient(this.config.poolId, this.config.clientId, this.logger)

    this.apiClient =
      apiClient ??
      new ApiClient(
        sudoUserClient,
        this.config.region,
        this.config.apiUrl,
        this.logger,
        link,
      )
  }

  private async signIn(
    username: string,
    key: ArrayBuffer,
    password: ArrayBuffer,
    authenticationSalt: ArrayBuffer,
    pbkdfRounds: number,
  ): Promise<string> {
    this.logger.info(
      'Signing into Secure Vault authentication provider to obtain an OTP.',
    )

    // Generate the authentication secret.
    const secret = await this.securityProvider.generateAuthenticationSecret(
      key,
      password,
      authenticationSalt,
      pbkdfRounds,
    )

    // Perform SRP based authentication with the generated secret to obtain a OTP
    // in the form of ID token.
    const tokens = await this.authClient.signIn(username, Base64.encode(secret))

    // Zero out sensitive data that's no longer needed.
    new Uint8Array(secret).fill(0)
    return tokens.idToken
  }

  async getInitializationData(): Promise<InitializationData | undefined> {
    // Return the cached initialization data if one exists otherwise fetch
    // it from the backend.
    if (this.initializationData) {
      return this.initializationData
    } else {
      this.logger.info('Retrieving the client initialization data.')

      const initializationData = await this.apiClient.getInitializationData()
      if (initializationData) {
        this.initializationData = {
          owner: initializationData.owner,
          authenticationSalt: Base64.decode(
            initializationData.authenticationSalt,
          ),
          encryptionSalt: Base64.decode(initializationData.encryptionSalt),
          pbkdfRounds: initializationData.pbkdfRounds,
        }
        return this.initializationData
      } else {
        return undefined
      }
    }
  }

  async register(key: ArrayBuffer, password: ArrayBuffer): Promise<string> {
    this.logger.info('Registering a vault user.')

    const token = this.sudoUserClient.getIdToken()
    const sub = this.sudoUserClient.getSubject()
    if (token && sub) {
      const authenticationSalt =
        this.securityProvider.generateKeyDerivationSalt()
      const encryptionSalt = this.securityProvider.generateKeyDerivationSalt()
      const secret = await this.securityProvider.generateAuthenticationSecret(
        key,
        password,
        authenticationSalt,
        this.pbkdfRounds,
      )

      const username = await this.authClient.register(
        sub,
        Base64.encode(secret),
        token,
        Base64.encode(authenticationSalt),
        Base64.encode(encryptionSalt),
        this.pbkdfRounds,
      )

      new Uint8Array(secret).fill(0)

      this.initializationData = {
        owner: username,
        authenticationSalt,
        encryptionSalt,
        pbkdfRounds: this.pbkdfRounds,
      }

      return username
    } else {
      throw new NotSignedInError()
    }
  }

  async isRegistered(): Promise<boolean> {
    if (this.initializationData) {
      return true
    } else {
      const initializationData = await this.getInitializationData()
      if (initializationData) {
        return true
      } else {
        return false
      }
    }
  }

  async createVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    blob: ArrayBuffer,
    blobFormat: string,
    ownershipProof: string,
  ): Promise<VaultMetadata> {
    this.logger.info('Creating a vault.')

    const initializationData = await this.getInitializationData()
    if (initializationData) {
      const token = await this.signIn(
        initializationData.owner,
        key,
        password,
        initializationData.authenticationSalt,
        initializationData.pbkdfRounds,
      )
      const { encrypted, iv } = await this.securityProvider.encrypt(
        key,
        password,
        initializationData.encryptionSalt,
        initializationData.pbkdfRounds,
        blob,
      )

      const vault = await this.apiClient.createVault({
        token,
        ownershipProofs: [ownershipProof],
        encryptionMethod:
          this.securityProvider.getEncryptionAlgorithmSpecifier(),
        blobFormat,
        blob: Base64.encode(Buffer.concat(encrypted, iv)),
      })

      return {
        id: vault.id,
        owner: vault.owner,
        version: vault.version,
        blobFormat: vault.blobFormat,
        createdAt: new Date(vault.createdAtEpochMs),
        updatedAt: new Date(vault.updatedAtEpochMs),
        owners: vault.owners.map(
          (owner) =>
            <Owner>{
              id: owner.id,
              issuer: owner.issuer,
            },
        ),
      }
    } else {
      throw new NotRegisteredError()
    }
  }

  async updateVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
    version: number,
    blob: ArrayBuffer,
    blobFormat: string,
  ): Promise<VaultMetadata> {
    this.logger.info('Updating a vault.', { id, version })

    const initializationData = await this.getInitializationData()
    if (initializationData) {
      const token = await this.signIn(
        initializationData.owner,
        key,
        password,
        initializationData.authenticationSalt,
        initializationData.pbkdfRounds,
      )

      const { encrypted, iv } = await this.securityProvider.encrypt(
        key,
        password,
        initializationData.encryptionSalt,
        initializationData.pbkdfRounds,
        blob,
      )

      const vault = await this.apiClient.updateVault({
        token,
        id,
        expectedVersion: version,
        encryptionMethod:
          this.securityProvider.getEncryptionAlgorithmSpecifier(),
        blobFormat,
        blob: Base64.encode(Buffer.concat(encrypted, iv)),
      })

      return {
        id: vault.id,
        owner: vault.owner,
        version: vault.version,
        blobFormat: vault.blobFormat,
        createdAt: new Date(vault.createdAtEpochMs),
        updatedAt: new Date(vault.updatedAtEpochMs),
        owners: vault.owners.map(
          (owner) =>
            <Owner>{
              id: owner.id,
              issuer: owner.issuer,
            },
        ),
      }
    } else {
      throw new NotRegisteredError()
    }
  }

  async deleteVault(id: string): Promise<VaultMetadata | undefined> {
    this.logger.info('Deleting a vault.', { id })

    const vault = await this.apiClient.deleteVault({ id: id })
    return vault
      ? {
          id: vault.id,
          owner: vault.owner,
          version: vault.version,
          blobFormat: vault.blobFormat,
          createdAt: new Date(vault.createdAtEpochMs),
          updatedAt: new Date(vault.updatedAtEpochMs),
          owners: vault.owners.map(
            (owner) =>
              <Owner>{
                id: owner.id,
                issuer: owner.issuer,
              },
          ),
        }
      : undefined
  }

  async getVault(
    key: ArrayBuffer,
    password: ArrayBuffer,
    id: string,
  ): Promise<Vault | undefined> {
    this.logger.info('Retrieving a vault.', { id })

    const initializationData = await this.getInitializationData()
    if (initializationData) {
      const token = await this.signIn(
        initializationData.owner,
        key,
        password,
        initializationData.authenticationSalt,
        initializationData.pbkdfRounds,
      )
      const vault = await this.apiClient.getVault(token, id)
      if (vault) {
        if (
          this.securityProvider.getEncryptionAlgorithmSpecifier() ===
          vault.encryptionMethod
        ) {
          const blob = Base64.decode(vault.blob)
          const { lhs, rhs } = Buffer.split(
            blob,
            blob.byteLength - this.securityProvider.getIVLength(),
          )
          const decrypted = await this.securityProvider.decrypt(
            key,
            password,
            initializationData.encryptionSalt,
            initializationData.pbkdfRounds,
            rhs,
            lhs,
          )
          return {
            id: vault.id,
            version: vault.version,
            createdAt: new Date(vault.createdAtEpochMs),
            updatedAt: new Date(vault.updatedAtEpochMs),
            owner: vault.owner,
            blobFormat: vault.blobFormat,
            blob: decrypted,
            owners: vault.owners.map(
              (owner) =>
                <Owner>{
                  id: owner.id,
                  issuer: owner.issuer,
                },
            ),
          }
        } else {
          throw new InvalidVaultError()
        }
      } else {
        return undefined
      }
    } else {
      throw new NotRegisteredError()
    }
  }

  async listVaults(key: ArrayBuffer, password: ArrayBuffer): Promise<Vault[]> {
    this.logger.info('Listing vaults.')

    const initializationData = await this.getInitializationData()
    if (initializationData) {
      const token = await this.signIn(
        initializationData.owner,
        key,
        password,
        initializationData.authenticationSalt,
        initializationData.pbkdfRounds,
      )
      const encryptedVaults = await this.apiClient.listVaults(token)
      const vaults: Vault[] = []
      if (encryptedVaults) {
        for (const encryptedVault of encryptedVaults) {
          if (
            this.securityProvider.getEncryptionAlgorithmSpecifier() ===
            encryptedVault.encryptionMethod
          ) {
            const blob = Base64.decode(encryptedVault.blob)
            const { lhs, rhs } = Buffer.split(
              blob,
              blob.byteLength - this.securityProvider.getIVLength(),
            )
            const decrypted = await this.securityProvider.decrypt(
              key,
              password,
              initializationData.encryptionSalt,
              initializationData.pbkdfRounds,
              rhs,
              lhs,
            )
            vaults.push({
              id: encryptedVault.id,
              version: encryptedVault.version,
              createdAt: new Date(encryptedVault.createdAtEpochMs),
              updatedAt: new Date(encryptedVault.updatedAtEpochMs),
              owner: encryptedVault.owner,
              blobFormat: encryptedVault.blobFormat,
              blob: decrypted,
              owners: encryptedVault.owners.map(
                (owner) =>
                  <Owner>{
                    id: owner.id,
                    issuer: owner.issuer,
                  },
              ),
            })
          } else {
            throw new InvalidVaultError()
          }
        }
      }
      return vaults
    } else {
      throw new NotRegisteredError()
    }
  }

  async listVaultsMetadataOnly(): Promise<VaultMetadata[]> {
    this.logger.info('Listing vaults (metdata only).')

    const vaults = await this.apiClient.listVaultsMetadataOnly()
    return vaults.map(
      (vault) =>
        <VaultMetadata>{
          id: vault.id,
          version: vault.version,
          blobFormat: vault.blobFormat,
          createdAt: new Date(vault.createdAtEpochMs),
          updatedAt: new Date(vault.updatedAtEpochMs),
          owners: vault.owners.map(
            (owner) =>
              <Owner>{
                id: owner.id,
                issuer: owner.issuer,
              },
          ),
        },
    )
  }

  async changeVaultPassword(
    key: ArrayBuffer,
    oldPassword: ArrayBuffer,
    newPassword: ArrayBuffer,
  ): Promise<void> {
    this.logger.info('Changing the vault password.')

    const initializationData = await this.getInitializationData()
    if (initializationData) {
      const sub = this.sudoUserClient.getSubject()

      if (sub) {
        // First download all vaults so we can re-encrypt them using the new password.
        const vaults = await this.listVaults(key, oldPassword)

        // Change the authentication password.
        const oldPasswordSecret =
          await this.securityProvider.generateAuthenticationSecret(
            key,
            oldPassword,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds,
          )
        const newPasswordSecret =
          await this.securityProvider.generateAuthenticationSecret(
            key,
            newPassword,
            initializationData.authenticationSalt,
            initializationData.pbkdfRounds,
          )
        await this.authClient.changePassword(
          sub,
          Base64.encode(oldPasswordSecret),
          Base64.encode(newPasswordSecret),
        )

        // Re-encrypt and update vaults.
        await Promise.all(
          vaults.map((vault) =>
            this.updateVault(
              key,
              newPassword,
              vault.id,
              vault.version,
              vault.blob,
              vault.blobFormat,
            ),
          ),
        )
      } else {
        throw new NotSignedInError()
      }
    } else {
      throw new NotRegisteredError()
    }
  }

  reset(): void {
    this.initializationData = undefined
    this.apiClient.reset()
  }

  async deregister(): Promise<void> {
    await this.apiClient.deregister()
    this.reset()
  }
}
