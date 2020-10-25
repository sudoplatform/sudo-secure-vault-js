import { DefaultSudoSecureVaultClient } from '../../src/vault/vaultClient'
import { DefaultSudoUserClient } from '@sudoplatform/sudo-user'
import { DefaultSudoProfilesClient } from '@sudoplatform/sudo-profiles'
import { DefaultConfigurationManager } from '@sudoplatform/sudo-common'
import { readFileSync, existsSync } from 'fs'
import { v4 } from 'uuid'
import Storage from 'dom-storage'
import { TESTAuthenticationProvider } from '@sudoplatform/sudo-user/lib/user/auth-provider'
import { Sudo } from '@sudoplatform/sudo-profiles/lib/sudo/sudo'
import { DefaultApiClientManager } from '@sudoplatform/sudo-api-client'
import {
  InvalidOwnershipProofError,
  NotAuthorizedError,
  VersionMismatchError,
} from '../../src/global/error'
global.localStorage = new Storage(null, { strict: true })
global.sessionStorage = new Storage(null, { strict: true })
global.crypto = require('isomorphic-webcrypto')

global.btoa = (b) => Buffer.from(b).toString('base64')
global.atob = (a) => Buffer.from(a, 'base64').toString()

function bufferToString(buffer) {
  return String.fromCharCode.apply(null, new Uint16Array(buffer))
}

function stringToBuffer(str: string) {
  const buffer = new ArrayBuffer(str.length * 2)
  const array = new Uint16Array(buffer)
  for (let i = 0; i < str.length; i++) {
    array[i] = str.charCodeAt(i)
  }
  return buffer
}

describe('SudoSecureVaultClient', () => {
  const configFilePath = 'identity-system-test-config/sudoplatformconfig.json'
  const testKeyPath = 'identity-system-test-config/register_key.private'
  const testKeyIdPath = 'identity-system-test-config/register_key.id'
  if (
    existsSync(configFilePath) &&
    existsSync(testKeyPath) &&
    existsSync(testKeyIdPath)
  ) {
    const config = readFileSync(configFilePath, 'utf-8')
    const testKey = readFileSync(testKeyPath, 'ascii').trim()
    const testKeyId = readFileSync(testKeyIdPath, 'ascii').trim()

    DefaultConfigurationManager.getInstance().setConfig(config)

    const sudoUserClient = new DefaultSudoUserClient()

    const apiClientManager = DefaultApiClientManager.getInstance()
    apiClientManager.setAuthClient(sudoUserClient)
    const apiClient = apiClientManager.getClient({
      disableOffline: true,
    })

    const sudoProfilesClient = new DefaultSudoProfilesClient(
      sudoUserClient,
      apiClient,
    )

    const client = new DefaultSudoSecureVaultClient(sudoUserClient)

    const key = new Uint8Array(new ArrayBuffer(16))

    beforeAll(async (): Promise<void> => {
      const testAuthenticationProvider = new TESTAuthenticationProvider(
        'mytest',
        testKey,
        testKeyId,
      )

      await sudoUserClient.registerWithAuthenticationProvider(
        testAuthenticationProvider,
        v4(),
      )

      await sudoUserClient.signInWithKey()
      client.reset()
    }, 30000)

    afterEach(async (): Promise<void> => {
      await client.deregister()
    }, 30000)

    afterAll(
      async (): Promise<void> => {
        await sudoUserClient.deregister()
      },
    )

    it('Register a vault user.', async () => {
      await client.register(key, stringToBuffer('passw0rd'))
      expect(await client.isRegistered()).toBeTruthy()
    }, 30000)

    it('Create, update, get, list and delete a vault.', async () => {
      await client.register(key, stringToBuffer('passw0rd'))
      expect(await client.isRegistered()).toBeTruthy()

      const sudo = await sudoProfilesClient.createSudo(new Sudo())

      const ownershipProof = await sudoProfilesClient.getOwnershipProof(
        sudo.id,
        'sudoplatform.secure-vault.vault',
      )

      let vaultMetadata = await client.createVault(
        key,
        stringToBuffer('passw0rd'),
        stringToBuffer('dummy_blob_1'),
        'text/utf8',
        ownershipProof,
      )

      expect(vaultMetadata.version).toBe(1)
      expect(vaultMetadata.blobFormat).toBe('text/utf8')

      const vault = await client.getVault(
        key,
        stringToBuffer('passw0rd'),
        vaultMetadata.id,
      )

      expect(vault.id).toBe(vaultMetadata.id)
      expect(vault.version).toBe(1)
      expect(bufferToString(vault.blob)).toBe('dummy_blob_1')
      expect(vault.blobFormat).toBe('text/utf8')

      vaultMetadata = await client.updateVault(
        key,
        stringToBuffer('passw0rd'),
        vaultMetadata.id,
        vaultMetadata.version,
        stringToBuffer('dummy_blob_2'),
        'text/utf8',
      )

      expect(vaultMetadata.version).toBe(2)
      expect(vaultMetadata.blobFormat).toBe('text/utf8')

      let vaults = await client.listVaults(key, stringToBuffer('passw0rd'))

      expect(vaults.length).toBe(1)
      expect(vaults[0].id).toBe(vaultMetadata.id)
      expect(vaults[0].version).toBe(2)
      expect(bufferToString(vaults[0].blob)).toBe('dummy_blob_2')
      expect(vaults[0].blobFormat).toBe('text/utf8')

      let vaultsMetadata = await client.listVaultsMetadataOnly()

      expect(vaultsMetadata.length).toBe(1)
      expect(vaultsMetadata[0].id).toBe(vaultMetadata.id)
      expect(vaultsMetadata[0].version).toBe(2)
      expect(vaultsMetadata[0].blobFormat).toBe('text/utf8')

      const deleted = await client.deleteVault(vaultMetadata.id)

      expect(deleted.id).toBe(vaultMetadata.id)
      expect(deleted.version).toBe(2)
      expect(deleted.blobFormat).toBe('text/utf8')

      vaults = await client.listVaults(key, stringToBuffer('passw0rd'))

      expect(vaults.length).toBe(0)

      vaultsMetadata = await client.listVaultsMetadataOnly()
      expect(vaultsMetadata.length).toBe(0)
    }, 30000)

    it('Change vault password.', async () => {
      await client.register(key, stringToBuffer('passw0rd'))
      expect(await client.isRegistered()).toBeTruthy()

      const sudo = await sudoProfilesClient.createSudo(new Sudo())

      const ownershipProof = await sudoProfilesClient.getOwnershipProof(
        sudo.id,
        'sudoplatform.secure-vault.vault',
      )

      const vaultMetadata = await client.createVault(
        key,
        stringToBuffer('passw0rd'),
        stringToBuffer('dummy_blob_1'),
        'text/utf8',
        ownershipProof,
      )

      expect(vaultMetadata.version).toBe(1)
      expect(vaultMetadata.blobFormat).toBe('text/utf8')

      await client.changeVaultPassword(
        key,
        stringToBuffer('passw0rd'),
        stringToBuffer('passw1rd'),
      )

      const vault = await client.getVault(
        key,
        stringToBuffer('passw1rd'),
        vaultMetadata.id,
      )

      expect(vault.id).toBe(vaultMetadata.id)
      expect(vault.version).toBe(2)
      expect(bufferToString(vault.blob)).toBe('dummy_blob_1')
      expect(vault.blobFormat).toBe('text/utf8')
    }, 60000)

    it('Access vault with wrong password or wrong key.', async () => {
      await client.register(key, stringToBuffer('passw0rd'))
      expect(await client.isRegistered()).toBeTruthy()

      try {
        await client.listVaults(key, stringToBuffer('passw1rd'))
      } catch (err) {
        expect(err).toBeInstanceOf(NotAuthorizedError)
      }

      try {
        const wrongKey = new Uint8Array(new ArrayBuffer(16))
        wrongKey[0] = 1
        await client.listVaults(wrongKey, stringToBuffer('passw0rd'))
      } catch (err) {
        expect(err).toBeInstanceOf(NotAuthorizedError)
      }
    }, 60000)

    it('Create a vault with invalid ownership proof.', async () => {
      await client.register(key, stringToBuffer('passw0rd'))
      expect(await client.isRegistered()).toBeTruthy()

      try {
        await client.createVault(
          key,
          stringToBuffer('passw0rd'),
          stringToBuffer('dummy_blob'),
          'text/utf8',
          'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQifQ.eyJvd25lciI6Ijc4YzFiNzFlLTFjNzMtNDhkYS05ZGQxLTFiNTc1ZGFjNjFjNSIsImlhdCI6MTYwMTQ1MTY4NywiZXhwIjoxNjAyNjYxMjg3LCJhdWQiOiJzdWRvcGxhdGZvcm0uc2VjdXJldmF1bHRzZXJ2aWNlIiwiaXNzIjoic3Vkb3BsYXRmb3JtLnN1ZG9zZXJ2aWNlIiwic3ViIjoiOTFjMTI4M2UtYmM3Ny00NzgxLWJiYzctZDQ0YzBmOTkwMmY4IiwianRpIjoiYTFmOGI5NzYtYzIyOS00MzkzLWFmYWQtMGE5NDMxMTczMTk1In0.hYEdFTRGdM9tUuVs0M5Id6iHo2ms18jxcYVbM3vAoky9BitVyQ2dzzY_ZJbREAXNW8VgOh0Wv_Uq-Kiw_6tlcPwRUeYVLHeQ97Ozo6z2COJaNGncNQg9m0ulfVYbvIK_TB99VS09wMvLWCntWldYFc87uM5aogw6_5uJZyB8gEtw1tN80XRBCg5Q_5stQDsCuCE6zc20aNZJ0RoRKNW6u6HdmtWaMO8o2XR0JiAzjzyaMtikJamzZYI-w6rzowk5BbBPPmwb2dp5yIcres6jRvcZZWm7A14NEQIOiKv8QlN7ocw_Ki8p2-oivQgWPkysZB0DtAvASH8_KGpVZHTM5Q',
        )
      } catch (err) {
        expect(err).toBeInstanceOf(InvalidOwnershipProofError)
      }
    }, 30000)

    it('Update a vault with wrong version.', async () => {
      await client.register(key, stringToBuffer('passw0rd'))
      expect(await client.isRegistered()).toBeTruthy()

      const sudo = await sudoProfilesClient.createSudo(new Sudo())

      const ownershipProof = await sudoProfilesClient.getOwnershipProof(
        sudo.id,
        'sudoplatform.secure-vault.vault',
      )

      let vaultMetadata = await client.createVault(
        key,
        stringToBuffer('passw0rd'),
        stringToBuffer('dummy_blob'),
        'text/utf8',
        ownershipProof,
      )

      expect(vaultMetadata.version).toBe(1)
      expect(vaultMetadata.blobFormat).toBe('text/utf8')

      try {
        vaultMetadata = await client.updateVault(
          key,
          stringToBuffer('passw0rd'),
          vaultMetadata.id,
          2,
          stringToBuffer('dummy_blob'),
          'text/utf8',
        )
        fail('Expected error not thrown.')
      } catch (err) {
        expect(err).toBeInstanceOf(VersionMismatchError)
      }
    }, 30000)
  } else {
    it('Skip all tests.', () => {
      console.log(
        'No sudoplatformconfig.json, test key and test key ID file found. Skipping all integration tests.',
      )
    })
  }
})
