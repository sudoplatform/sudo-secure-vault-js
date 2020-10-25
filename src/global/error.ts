import { GraphQLError } from 'graphql'

export type AppSyncError = GraphQLError & {
  errorType?: string | null
}

/**
 * The user is not authorized to perform the requested operation. This maybe
 * due to specifying the wrong key deriving key or password.
 */
export class NotAuthorizedError extends Error {
  constructor() {
    super('User is not authorized perform the requested operation.')
    this.name = 'NotAuthorizedError'
  }
}

/**
 * The user is not registered with Secure Vault Service.
 */
export class NotRegisteredError extends Error {
  constructor() {
    super('User is not registered with Secure Vault Service.')
    this.name = 'NotRegisteredError'
  }
}

/**
 * The version of the vault that's being updated does not match the version
 * stored in the backed. It is likely that another client updated the vault
 * first so the caller should reconcile the changes before attempting to
 * update the vault.
 */
export class VersionMismatchError extends Error {
  constructor() {
    super('Expected object version does not match the actual object version.')
    this.name = 'VersionMismatchError'
  }
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
 * Indicates the operation requires the user to be signed in but the user is
 * currently not signed in.
 */
export class NotSignedInError extends Error {
  constructor() {
    super('Not signed in.')
    this.name = 'NotSignedInError'
  }
}

/**
 * Indicates that the user was registered but is not confirmed due to not
 * passing all the required validation.
 */
export class UserNotConfirmedError extends Error {
  constructor() {
    super('User not confirmed.')
    this.name = 'UserNotConfirmedError'
  }
}

/**
 * Indicates that the ownership proof was invalid.
 */
export class InvalidOwnershipProofError extends Error {
  constructor() {
    super('Ownership proof was invalid.')
    this.name = 'InvalidOwnershipProofError'
  }
}

/**
 * Indicates that the user does not have sufficient entitlements to perform
 * the requested operation.
 */
export class PolicyError extends Error {
  constructor() {
    super(
      'Service policy prevented the requested operation from completing. This may be due to the user having insufficient entitlements.',
    )
    this.name = 'PolicyError'
  }
}

/**
 * Indicates the GraphQL API return an error that's not recognized by the client.
 */
export class UnknownGraphQLError extends Error {
  constructor(cause: AppSyncError) {
    super(`type: ${cause.errorType}, message: ${cause.message}`)
    this.name = 'GraphQLError'
  }
}

/**
 * Indicates that an internal server error caused the operation to fail. The error
 * is possibly transient and retrying at a later time may cause the operation to
 * complete successfully.
 */
export class ServiceError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ServiceError'
  }
}

/**
 * An unexpected error was encountered. This may result from programmatic error
 * and is unlikley to be user recoverable.
 */
export class FatalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'FatalError'
  }
}
