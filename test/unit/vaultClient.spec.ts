import {
  SudoSecureVaultClient,
  DefaultSudoSecureVaultClient,
} from '../../src/vault/vaultClient'
import { ApiClient } from '../../src/client/apiClient'
import { AuthClient } from '../../src/client/authClient'
import { mock, when, instance, reset, deepEqual } from 'ts-mockito'
import { Base64 } from '../../src/util/base64'
import { WebCryptoSecurityProvider } from '../../src/security/webCryptoSecurityProvider'
import { SudoUserClient } from '@sudoplatform/sudo-user'
import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import { NotSignedInError } from '@sudoplatform/sudo-common'

describe('SudoSecureVaultClient', () => {
  const sudoUserClientMock: SudoUserClient = mock()
  const apiClientMock: ApiClient = mock()
  const authClientMock: AuthClient = mock()
  const securityProviderMock: WebCryptoSecurityProvider = mock()
  const sudoUserClient = instance(sudoUserClientMock)
  const apiClient = instance(apiClientMock)
  const authClient = instance(authClientMock)
  const securityProvider = instance(securityProviderMock)

  const config = {
    secureVaultService: {
      region: '',
      poolId: '',
      clientId: '',
      apiUrl: '',
      pbkdfRounds: 100000,
    },
  }

  DefaultConfigurationManager.getInstance().setConfig(JSON.stringify(config))

  const client: SudoSecureVaultClient = new DefaultSudoSecureVaultClient(
    sudoUserClient,
    null,
    authClient,
    apiClient,
    securityProvider,
  )

  beforeEach((): void => {
    reset(sudoUserClientMock)
    reset(apiClientMock)
    reset(authClientMock)
    reset(securityProviderMock)
    client.reset()
  })

  afterEach((): void => {
    reset(sudoUserClientMock)
    reset(apiClientMock)
    reset(authClientMock)
    reset(securityProviderMock)
    client.reset()
  })

  describe('register()', () => {
    const key = Buffer.from('dummy_key', 'utf8')
    const password = Buffer.from('dummy_password', 'utf8')
    const salt = Buffer.from('dummy_salt', 'utf8')
    const secret = Buffer.from('dummy_secret', 'utf8')

    it('Registration completes successfully.', async () => {
      when(sudoUserClientMock.getIdToken()).thenReturn('dummy_id_token')
      when(sudoUserClientMock.getSubject()).thenReturn('dummy_sub')
      when(securityProviderMock.generateKeyDerivationSalt()).thenReturn(salt)

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          password,
          deepEqual(new Uint8Array(salt)),
          100000,
        ),
      ).thenResolve(secret)

      when(
        authClientMock.register(
          'dummy_sub',
          Base64.encode(secret),
          'dummy_id_token',
          Base64.encode(salt),
          Base64.encode(salt),
          100000,
        ),
      ).thenResolve('dummy_sub')

      const username = await client.register(key, password)
      expect(username).toBe('dummy_sub')

      expect(await client.isRegistered()).toBeTruthy()

      const initializationData = await client.getInitializationData()
      if (initializationData) {
        expect(
          Buffer.from(initializationData.authenticationSalt).toString('utf8'),
        ).toBe('dummy_salt')
        expect(
          Buffer.from(initializationData.encryptionSalt).toString('utf8'),
        ).toBe('dummy_salt')
        expect(initializationData.pbkdfRounds).toBe(100000)
      } else {
        fail('Initialization data not found.')
      }
    })
  })

  describe('isRegistered()', () => {
    it('Registered.', async () => {
      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_owner',
        authenticationSalt: Base64.encode(
          Buffer.from('authentication_salt', 'utf8'),
        ),
        encryptionSalt: Base64.encode(Buffer.from('encryption_salt', 'utf8')),
        pbkdfRounds: 100000,
      })

      expect(await client.isRegistered()).toBeTruthy()

      const initializationData = await client.getInitializationData()
      if (initializationData) {
        expect(
          Buffer.from(initializationData.authenticationSalt).toString('utf8'),
        ).toBe('authentication_salt')
        expect(
          Buffer.from(initializationData.encryptionSalt).toString('utf8'),
        ).toBe('encryption_salt')
        expect(initializationData.pbkdfRounds).toBe(100000)
      } else {
        fail('Initialization data not found.')
      }
    })
    it('Not registered.', async () => {
      when(apiClientMock.getInitializationData()).thenResolve(undefined)

      expect(await client.isRegistered()).toBeFalsy()

      const initializationData = await client.getInitializationData()
      expect(initializationData).toBeFalsy()
    })
  })

  describe('createVault()', () => {
    it('Create a vault.', async () => {
      const key = Buffer.from('dummy_key', 'utf8')
      const password = Buffer.from('dummy_password', 'utf8')
      const authenticationSalt = Buffer.from('authentication_salt', 'utf8')
      const encryptionSalt = Buffer.from('encryption_salt', 'utf8')
      const secret = Buffer.from('dummy_secret', 'utf8')
      const blob = Buffer.from('dummy_blob', 'utf8')
      const encrypted = Buffer.from('dummy_encrypted', 'utf8')
      const iv = Buffer.from('dummy_iv', 'utf8')
      const combined = Buffer.concat([encrypted, iv])

      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          password,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(secret)

      when(
        authClientMock.signIn('dummy_user', Base64.encode(secret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(
        securityProviderMock.encrypt(
          key,
          password,
          deepEqual(new Uint8Array(encryptionSalt)),
          100000,
          blob,
        ),
      ).thenResolve({ encrypted, iv })

      when(securityProviderMock.getEncryptionAlgorithmSpecifier()).thenReturn(
        'AES/CBC/PKCS7Padding',
      )

      when(
        apiClientMock.createVault(
          deepEqual({
            token: 'dummy_id_token',
            ownershipProofs: ['dummy_ownership_proof'],
            blob: Base64.encode(combined),
            blobFormat: 'dummy_format',
            encryptionMethod: 'AES/CBC/PKCS7Padding',
          }),
        ),
      ).thenResolve({
        id: 'dummy_id',
        version: 1,
        owner: 'dummy_owner',
        encryptionMethod: 'AES/CBC/PKCS7Padding',
        blobFormat: 'dummy_format',
        createdAtEpochMs: 1,
        updatedAtEpochMs: 2,
        owners: [{ id: 'dummy_user', issuer: 'sudoplatform.identityservice' }],
      })

      const vault = await client.createVault(
        key,
        password,
        blob,
        'dummy_format',
        'dummy_ownership_proof',
      )

      expect(vault.id).toBe('dummy_id')
      expect(vault.version).toBe(1)
      expect(vault.owner).toBe('dummy_owner')
      expect(vault.blobFormat).toBe('dummy_format')
      expect(vault.createdAt.getTime()).toBe(1)
      expect(vault.updatedAt.getTime()).toBe(2)
      expect(vault.owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])
    })
  })

  describe('updateVault()', () => {
    it('Update an existing vault.', async () => {
      const key = Buffer.from('dummy_key', 'utf8')
      const password = Buffer.from('dummy_password', 'utf8')
      const authenticationSalt = Buffer.from('authentication_salt', 'utf8')
      const encryptionSalt = Buffer.from('encryption_salt', 'utf8')
      const secret = Buffer.from('dummy_secret', 'utf8')
      const blob = Buffer.from('dummy_blob', 'utf8')
      const encrypted = Buffer.from('dummy_encrypted', 'utf8')
      const iv = Buffer.from('dummy_iv', 'utf8')
      const combined = Buffer.concat([encrypted, iv])

      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          password,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(secret)

      when(
        authClientMock.signIn('dummy_user', Base64.encode(secret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(
        securityProviderMock.encrypt(
          key,
          password,
          deepEqual(new Uint8Array(encryptionSalt)),
          100000,
          blob,
        ),
      ).thenResolve({ encrypted, iv })

      when(securityProviderMock.getEncryptionAlgorithmSpecifier()).thenReturn(
        'AES/CBC/PKCS7Padding',
      )

      when(
        apiClientMock.updateVault(
          deepEqual({
            token: 'dummy_id_token',
            id: 'dummy_id',
            expectedVersion: 1,
            blob: Base64.encode(combined),
            blobFormat: 'dummy_format',
            encryptionMethod: 'AES/CBC/PKCS7Padding',
          }),
        ),
      ).thenResolve({
        id: 'dummy_id',
        version: 2,
        owner: 'dummy_owner',
        encryptionMethod: 'AES/CBC/PKCS7Padding',
        blobFormat: 'dummy_format',
        createdAtEpochMs: 1,
        updatedAtEpochMs: 2,
        owners: [{ id: 'dummy_user', issuer: 'sudoplatform.identityservice' }],
      })

      const vault = await client.updateVault(
        key,
        password,
        'dummy_id',
        1,
        blob,
        'dummy_format',
      )

      expect(vault.id).toBe('dummy_id')
      expect(vault.version).toBe(2)
      expect(vault.owner).toBe('dummy_owner')
      expect(vault.blobFormat).toBe('dummy_format')
      expect(vault.createdAt.getTime()).toBe(1)
      expect(vault.updatedAt.getTime()).toBe(2)
      expect(vault.owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])
    })
  })

  describe('listVaultsMetadataOnly()', () => {
    it('0 vault.', async () => {
      when(apiClientMock.listVaultsMetadataOnly()).thenResolve([])

      const vaults = await client.listVaultsMetadataOnly()
      expect(vaults.length).toBe(0)
    })

    it('Mutitple vaults.', async () => {
      when(apiClientMock.listVaultsMetadataOnly()).thenResolve([
        {
          id: 'dummy_id_1',
          version: 1,
          owner: 'dummy_owner',
          encryptionMethod: 'AES/CBC/PKCS7Padding',
          blobFormat: 'dummy_format',
          createdAtEpochMs: 1,
          updatedAtEpochMs: 2,
          owners: [
            { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
          ],
        },
        {
          id: 'dummy_id_2',
          version: 2,
          owner: 'dummy_owner',
          encryptionMethod: 'AES/CBC/PKCS7Padding',
          blobFormat: 'dummy_format',
          createdAtEpochMs: 1,
          updatedAtEpochMs: 2,
          owners: [
            { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
          ],
        },
      ])

      const vaults = await client.listVaultsMetadataOnly()
      expect(vaults.length).toBe(2)
      expect(vaults[0].id).toBe('dummy_id_1')
      expect(vaults[0].version).toBe(1)
      expect(vaults[0].blobFormat).toBe('dummy_format')
      expect(vaults[0].createdAt.getTime()).toBe(1)
      expect(vaults[0].updatedAt.getTime()).toBe(2)
      expect(vaults[0].owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])

      expect(vaults[1].id).toBe('dummy_id_2')
      expect(vaults[1].version).toBe(2)
      expect(vaults[1].blobFormat).toBe('dummy_format')
      expect(vaults[1].createdAt.getTime()).toBe(1)
      expect(vaults[1].updatedAt.getTime()).toBe(2)
      expect(vaults[1].owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])
    })
  })

  describe('deleteVault()', () => {
    it('Delete non existing vault.', async () => {
      when(
        apiClientMock.deleteVault(deepEqual({ id: 'dummy_id' })),
      ).thenResolve(undefined)

      const vault = await client.deleteVault('dummy_id')
      expect(vault).toBeFalsy()
    })

    it('Delete existing vault.', async () => {
      when(
        apiClientMock.deleteVault(deepEqual({ id: 'dummy_id' })),
      ).thenResolve({
        id: 'dummy_id',
        version: 1,
        owner: 'dummy_owner',
        encryptionMethod: 'AES/CBC/PKCS7Padding',
        blobFormat: 'dummy_format',
        createdAtEpochMs: 1,
        updatedAtEpochMs: 2,
        owners: [{ id: 'dummy_user', issuer: 'sudoplatform.identityservice' }],
      })

      const vault = await client.deleteVault('dummy_id')
      expect(vault).toBeTruthy()
      expect(vault?.id).toBe('dummy_id')
      expect(vault?.owner).toBe('dummy_owner')
      expect(vault?.version).toBe(1)
      expect(vault?.blobFormat).toBe('dummy_format')
      expect(vault?.createdAt.getTime()).toBe(1)
      expect(vault?.updatedAt.getTime()).toBe(2)
      expect(vault?.owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])
    })
  })

  describe('getVault()', () => {
    const key = Buffer.from('dummy_key', 'utf8')
    const password = Buffer.from('dummy_password', 'utf8')
    const authenticationSalt = Buffer.from('authentication_salt', 'utf8')
    const encryptionSalt = Buffer.from('encryption_salt', 'utf8')
    const secret = Buffer.from('dummy_secret', 'utf8')
    const blob = Buffer.from('dummy_blob', 'utf8')
    const encrypted = Buffer.from('dummy_encrypted', 'utf8')
    const iv = new ArrayBuffer(16)
    const combined = Buffer.concat([encrypted, new Uint8Array(iv).fill(0)])

    it('Get non existing vault.', async () => {
      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          password,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(secret)

      when(
        authClientMock.signIn('dummy_user', Base64.encode(secret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(apiClientMock.getVault('dummy_id_token', 'dummy_id')).thenResolve(
        undefined,
      )

      const vault = await client.getVault(key, password, 'dummy_id')
      expect(vault).toBeFalsy()
    })

    it('Get existing vault.', async () => {
      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          password,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(secret)

      when(
        authClientMock.signIn('dummy_user', Base64.encode(secret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(securityProviderMock.getEncryptionAlgorithmSpecifier()).thenReturn(
        'AES/CBC/PKCS7Padding',
      )

      when(securityProviderMock.getIVLength()).thenReturn(16)

      when(
        securityProviderMock.decrypt(
          key,
          password,
          deepEqual(new Uint8Array(encryptionSalt)),
          100000,
          deepEqual(new Uint8Array(iv)),
          deepEqual(new Uint8Array(encrypted)),
        ),
      ).thenResolve(blob)

      when(apiClientMock.getVault('dummy_id_token', 'dummy_id')).thenResolve({
        id: 'dummy_id',
        version: 1,
        owner: 'dummy_owner',
        encryptionMethod: 'AES/CBC/PKCS7Padding',
        blob: Base64.encode(combined),
        blobFormat: 'dummy_format',
        createdAtEpochMs: 1,
        updatedAtEpochMs: 2,
        owners: [{ id: 'dummy_user', issuer: 'sudoplatform.identityservice' }],
      })

      const vault = await client.getVault(key, password, 'dummy_id')
      expect(vault).toBeTruthy()
      expect(vault?.id).toBe('dummy_id')
      expect(vault?.owner).toBe('dummy_owner')
      expect(vault?.version).toBe(1)
      expect(vault?.blob).toBe(blob)
      expect(vault?.blobFormat).toBe('dummy_format')
      expect(vault?.createdAt.getTime()).toBe(1)
      expect(vault?.updatedAt.getTime()).toBe(2)
      expect(vault?.owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])
    })
  })

  describe('listVaults()', () => {
    const key = Buffer.from('dummy_key', 'utf8')
    const password = Buffer.from('dummy_password', 'utf8')
    const authenticationSalt = Buffer.from('authentication_salt', 'utf8')
    const encryptionSalt = Buffer.from('encryption_salt', 'utf8')
    const secret = Buffer.from('dummy_secret', 'utf8')
    const blob = Buffer.from('dummy_blob', 'utf8')
    const encrypted = Buffer.from('dummy_encrypted', 'utf8')
    const iv = new ArrayBuffer(16)
    const combined = Buffer.concat([encrypted, new Uint8Array(iv).fill(0)])

    it('0 vault.', async () => {
      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          password,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(secret)

      when(
        authClientMock.signIn('dummy_user', Base64.encode(secret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(apiClientMock.listVaults('dummy_id_token')).thenResolve(undefined)

      const vaults = await client.listVaults(key, password)
      expect(vaults.length).toBe(0)
    })

    it('Multiple vaults.', async () => {
      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          password,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(secret)

      when(
        authClientMock.signIn('dummy_user', Base64.encode(secret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(securityProviderMock.getEncryptionAlgorithmSpecifier()).thenReturn(
        'AES/CBC/PKCS7Padding',
      )

      when(securityProviderMock.getIVLength()).thenReturn(16)

      when(
        securityProviderMock.decrypt(
          key,
          password,
          deepEqual(new Uint8Array(encryptionSalt)),
          100000,
          deepEqual(new Uint8Array(iv)),
          deepEqual(new Uint8Array(encrypted)),
        ),
      ).thenResolve(blob)

      when(apiClientMock.listVaults('dummy_id_token')).thenResolve([
        {
          id: 'dummy_id_1',
          version: 1,
          owner: 'dummy_owner',
          encryptionMethod: 'AES/CBC/PKCS7Padding',
          blob: Base64.encode(combined),
          blobFormat: 'dummy_format',
          createdAtEpochMs: 1,
          updatedAtEpochMs: 2,
          owners: [
            { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
          ],
        },
        {
          id: 'dummy_id_2',
          version: 1,
          owner: 'dummy_owner',
          encryptionMethod: 'AES/CBC/PKCS7Padding',
          blob: Base64.encode(combined),
          blobFormat: 'dummy_format',
          createdAtEpochMs: 1,
          updatedAtEpochMs: 2,
          owners: [
            { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
          ],
        },
      ])

      const vaults = await client.listVaults(key, password)
      expect(vaults.length).toBe(2)
      expect(vaults[0].id).toBe('dummy_id_1')
      expect(vaults[0].owner).toBe('dummy_owner')
      expect(vaults[0].version).toBe(1)
      expect(vaults[0].blob).toBe(blob)
      expect(vaults[0].blobFormat).toBe('dummy_format')
      expect(vaults[0].createdAt.getTime()).toBe(1)
      expect(vaults[0].updatedAt.getTime()).toBe(2)
      expect(vaults[0].owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])

      expect(vaults[1].id).toBe('dummy_id_2')
      expect(vaults[1].owner).toBe('dummy_owner')
      expect(vaults[1].version).toBe(1)
      expect(vaults[1].blob).toBe(blob)
      expect(vaults[1].blobFormat).toBe('dummy_format')
      expect(vaults[1].createdAt.getTime()).toBe(1)
      expect(vaults[1].updatedAt.getTime()).toBe(2)
      expect(vaults[1].owners).toEqual([
        { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
      ])
    })
  })

  describe('changePassword()', () => {
    const key = Buffer.from('dummy_key', 'utf8')
    const oldPassword = Buffer.from('dummy_old_password', 'utf8')
    const newPassword = Buffer.from('dummy_new_password', 'utf8')
    const authenticationSalt = Buffer.from('authentication_salt', 'utf8')
    const encryptionSalt = Buffer.from('encryption_salt', 'utf8')
    const oldPasswordSecret = Buffer.from('dummy_old_secret', 'utf8')
    const newPasswordSecret = Buffer.from('dummy_new_secret', 'utf8')
    const blob = Buffer.from('dummy_blob', 'utf8')
    const encrypted = Buffer.from('dummy_encrypted', 'utf8')
    const iv = new ArrayBuffer(16)
    const combined = Buffer.concat([encrypted, new Uint8Array(iv).fill(0)])

    it('Change password completes successfully.', async () => {
      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(apiClientMock.getInitializationData()).thenResolve({
        owner: 'dummy_user',
        authenticationSalt: Base64.encode(authenticationSalt),
        encryptionSalt: Base64.encode(encryptionSalt),
        pbkdfRounds: 100000,
      })

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          oldPassword,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(oldPasswordSecret)

      when(
        securityProviderMock.generateAuthenticationSecret(
          key,
          newPassword,
          deepEqual(new Uint8Array(authenticationSalt)),
          100000,
        ),
      ).thenResolve(newPasswordSecret)

      when(sudoUserClientMock.getSubject()).thenReturn('dummy_user')

      when(
        authClientMock.signIn('dummy_user', Base64.encode(oldPasswordSecret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(securityProviderMock.getEncryptionAlgorithmSpecifier()).thenReturn(
        'AES/CBC/PKCS7Padding',
      )

      when(securityProviderMock.getIVLength()).thenReturn(16)

      when(
        securityProviderMock.decrypt(
          key,
          oldPassword,
          deepEqual(new Uint8Array(encryptionSalt)),
          100000,
          deepEqual(new Uint8Array(iv)),
          deepEqual(new Uint8Array(encrypted)),
        ),
      ).thenResolve(blob)

      when(apiClientMock.listVaults('dummy_id_token')).thenResolve([
        {
          id: 'dummy_id_1',
          version: 1,
          owner: 'dummy_owner',
          encryptionMethod: 'AES/CBC/PKCS7Padding',
          blob: Base64.encode(combined),
          blobFormat: 'dummy_format',
          createdAtEpochMs: 1,
          updatedAtEpochMs: 2,
          owners: [
            { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
          ],
        },
        {
          id: 'dummy_id_2',
          version: 1,
          owner: 'dummy_owner',
          encryptionMethod: 'AES/CBC/PKCS7Padding',
          blob: Base64.encode(combined),
          blobFormat: 'dummy_format',
          createdAtEpochMs: 1,
          updatedAtEpochMs: 2,
          owners: [
            { id: 'dummy_user', issuer: 'sudoplatform.identityservice' },
          ],
        },
      ])

      when(
        authClientMock.signIn('dummy_user', Base64.encode(newPasswordSecret)),
      ).thenResolve({
        idToken: 'dummy_id_token',
        accessToken: 'dummy_access_token',
      })

      when(
        securityProviderMock.encrypt(
          key,
          newPassword,
          deepEqual(new Uint8Array(encryptionSalt)),
          100000,
          blob,
        ),
      ).thenResolve({ encrypted, iv })

      when(securityProviderMock.getEncryptionAlgorithmSpecifier()).thenReturn(
        'AES/CBC/PKCS7Padding',
      )

      when(
        apiClientMock.updateVault(
          deepEqual({
            token: 'dummy_id_token',
            id: 'dummy_id_1',
            expectedVersion: 1,
            blob: Base64.encode(combined),
            blobFormat: 'dummy_format',
            encryptionMethod: 'AES/CBC/PKCS7Padding',
          }),
        ),
      ).thenResolve({
        id: 'dummy_id_1',
        version: 2,
        owner: 'dummy_owner',
        encryptionMethod: 'AES/CBC/PKCS7Padding',
        blobFormat: 'dummy_format',
        createdAtEpochMs: 1,
        updatedAtEpochMs: 2,
        owners: [{ id: 'dummy_user', issuer: 'sudoplatform.identityservice' }],
      })

      when(
        apiClientMock.updateVault(
          deepEqual({
            token: 'dummy_id_token',
            id: 'dummy_id_2',
            expectedVersion: 1,
            blob: Base64.encode(combined),
            blobFormat: 'dummy_format',
            encryptionMethod: 'AES/CBC/PKCS7Padding',
          }),
        ),
      ).thenResolve({
        id: 'dummy_id_2',
        version: 2,
        owner: 'dummy_owner',
        encryptionMethod: 'AES/CBC/PKCS7Padding',
        blobFormat: 'dummy_format',
        createdAtEpochMs: 1,
        updatedAtEpochMs: 2,
        owners: [{ id: 'dummy_user', issuer: 'sudoplatform.identityservice' }],
      })

      await client.changeVaultPassword(key, oldPassword, newPassword)
    })
  })

  describe('deregister()', () => {
    it('De-registration completes successfully.', async () => {
      when(apiClientMock.deregister()).thenResolve({ username: 'dummy_sub' })
      when(apiClientMock.getInitializationData()).thenResolve(undefined)

      await client.deregister()
      expect(await client.isRegistered()).toBeFalsy()
    })
  })

  it('unauthenticated API access', async () => {
    const config = {
      secureVaultService: {
        region: 'us-east-1',
        poolId: 'us-east-1_6NalHLdlq',
        clientId: 'pcg1ma18cluamqrif79viaj04',
        apiUrl:
          'https://u2ysyzwojzaahbsq5toulhdt4e.appsync-api.us-east-1.amazonaws.com/graphql',
        pbkdfRounds: 100000,
      },
    }

    const client: SudoSecureVaultClient = new DefaultSudoSecureVaultClient(
      sudoUserClient,
      config.secureVaultService,
      authClient,
    )

    when(sudoUserClientMock.isSignedIn()).thenResolve(false)

    try {
      await client.getInitializationData()
      fail('Expected error not thrown.')
    } catch (err) {
      expect(err).toBeInstanceOf(NotSignedInError)
    }

    try {
      await client.createVault(
        new Uint8Array(),
        new Uint8Array(),
        new Uint8Array(),
        '',
        '',
      )
      fail('Expected error not thrown.')
    } catch (err) {
      expect(err).toBeInstanceOf(NotSignedInError)
    }

    try {
      await client.updateVault(
        new Uint8Array(),
        new Uint8Array(),
        '',
        1,
        new Uint8Array(),
        '',
      )
      fail('Expected error not thrown.')
    } catch (err) {
      expect(err).toBeInstanceOf(NotSignedInError)
    }

    try {
      await client.deleteVault('')
      fail('Expected error not thrown.')
    } catch (err) {
      expect(err).toBeInstanceOf(NotSignedInError)
    }

    try {
      await client.listVaultsMetadataOnly()
      fail('Expected error not thrown.')
    } catch (err) {
      expect(err).toBeInstanceOf(NotSignedInError)
    }

    try {
      await client.listVaults(new Uint8Array(), new Uint8Array())
      fail('Expected error not thrown.')
    } catch (err) {
      expect(err).toBeInstanceOf(NotSignedInError)
    }

    try {
      await client.getVault(new Uint8Array(), new Uint8Array(), '')
      fail('Expected error not thrown.')
    } catch (err) {
      expect(err).toBeInstanceOf(NotSignedInError)
    }
  })
})
