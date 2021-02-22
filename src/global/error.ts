import { GraphQLError } from 'graphql'

export type AppSyncError = GraphQLError & {
  errorType?: string | null
}

/**
 * The vault data retrieved is invalid. This indicates the vault is corrupt or
 * is encrypted using a key that's not known to the client.
 */
export class InvalidVaultError extends Error {
  constructor() {
    super('Vault retrieved is invalid.')
    this.name = 'InvalidVaultError'
  }
}

/**
 * The vault user is already registered. This error can be thrown if `register`
 * API was called multiple times without first calling `deregister` API.
 */
export class AlreadyRegisteredError extends Error {
  constructor() {
    super('Vault user already registered.')
    this.name = 'AlreadyRegisteredError'
  }
}
