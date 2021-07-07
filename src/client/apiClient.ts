import { NormalizedCacheObject } from 'apollo-cache-inmemory'
import { ApolloLink } from 'apollo-link'
import { createHttpLink } from 'apollo-link-http'
import { AuthLink } from 'aws-appsync-auth-link'
import { createSubscriptionHandshakeLink } from 'aws-appsync-subscription-link'
import AWSAppSyncClient, { AUTH_TYPE } from 'aws-appsync'
import {
  VaultMetadata,
  CreateVaultMutation,
  UpdateVaultMutation,
  DeleteVaultMutation,
  GetInitializationDataQuery,
  InitializationData,
  GetVaultQuery,
  Vault,
  ListVaultsQuery,
  ListVaultsMetadataOnlyQuery,
  CreateVaultInput,
  UpdateVaultInput,
  DeleteVaultInput,
  CreateVaultDocument,
  UpdateVaultDocument,
  DeleteVaultDocument,
  GetInitializationDataDocument,
  GetVaultDocument,
  ListVaultsDocument,
  ListVaultsMetadataOnlyDocument,
  DeregisterMutation,
  DeregisterDocument,
  EntitlementsConsumption,
  GetEntitlementsForSvsQuery,
  GetEntitlementsForSvsDocument,
} from '../gen/graphqlTypes'
import {
  FatalError,
  NotSignedInError,
  VersionMismatchError,
  UnknownGraphQLError,
  ServiceError,
  AppSyncError,
  InvalidOwnershipProofError,
  InsufficientEntitlementsError,
  NotAuthorizedError,
  Logger,
  LimitExceededError,
  isAppSyncNetworkError,
  mapNetworkErrorToClientError,
} from '@sudoplatform/sudo-common'
import { SudoUserClient } from '@sudoplatform/sudo-user'
import {} from '@sudoplatform/sudo-entitlements'
import { ServerError } from '../global/error'

/**
 * AppSync wrapper to use to invoke Secure Vault Service APIs.
 */
export class ApiClient {
  private client: AWSAppSyncClient<NormalizedCacheObject>
  private readonly sudoUserClient: SudoUserClient
  private region: string
  private graphqlUrl: string
  private logger: Logger

  public constructor(
    sudoUserClient: SudoUserClient,
    region: string,
    graphqlUrl: string,
    logger: Logger,
    link?: ApolloLink,
  ) {
    this.sudoUserClient = sudoUserClient
    this.region = region
    this.graphqlUrl = graphqlUrl
    this.logger = logger

    this.client = this.createAppSyncClient(
      this.graphqlUrl,
      this.region,
      this.sudoUserClient,
      link,
    )
  }

  public async createVault(input: CreateVaultInput): Promise<VaultMetadata> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<CreateVaultMutation>({
        mutation: CreateVaultDocument,
        variables: { input },
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return result.data.createVault
    } else {
      throw new FatalError('createVault did not return any result.')
    }
  }

  public async updateVault(input: UpdateVaultInput): Promise<VaultMetadata> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<UpdateVaultMutation>({
        mutation: UpdateVaultDocument,
        variables: {
          input,
        },
        fetchPolicy: 'no-cache',
        errorPolicy: 'all',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return result.data.updateVault
    } else {
      throw new FatalError('createVault did not return any result.')
    }
  }

  public async deleteVault(
    input: DeleteVaultInput,
  ): Promise<VaultMetadata | undefined | null> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<DeleteVaultMutation>({
        mutation: DeleteVaultDocument,
        variables: { input },
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return result.data.deleteVault
    } else {
      throw new FatalError('createVault did not return any result.')
    }
  }

  public async getInitializationData(): Promise<
    InitializationData | undefined | null
  > {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.query<GetInitializationDataQuery>({
        query: GetInitializationDataDocument,
        variables: {},
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return result.data.getInitializationData
    } else {
      throw new FatalError('getInitializationData did not return any result.')
    }
  }

  public async getVault(
    token: string,
    id: string,
  ): Promise<Vault | null | undefined> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.query<GetVaultQuery>({
        query: GetVaultDocument,
        variables: { token, id },
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return result.data.getVault
    } else {
      throw new FatalError('getVault did not return any result.')
    }
  }

  public async listVaults(
    token: string,
    limit?: number,
    nextToken?: string,
  ): Promise<Vault[]> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.query<ListVaultsQuery>({
        query: ListVaultsDocument,
        variables: { token, limit, nextToken },
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      const vaults = result.data.listVaults?.items
      if (vaults) {
        return vaults
      } else {
        return []
      }
    } else {
      throw new FatalError('listVaults did not return any result.')
    }
  }

  public async listVaultsMetadataOnly(
    limit?: number,
    nextToken?: string,
  ): Promise<VaultMetadata[]> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.query<ListVaultsMetadataOnlyQuery>({
        query: ListVaultsMetadataOnlyDocument,
        variables: { limit, nextToken },
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      const vaults = result.data.listVaultsMetadataOnly?.items
      if (vaults) {
        return vaults
      } else {
        return []
      }
    } else {
      throw new FatalError('listVaultsMetadataOnly did not return any result.')
    }
  }

  public async deregister(): Promise<{ username: string }> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.mutate<DeregisterMutation>({
        mutation: DeregisterDocument,
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return { username: result.data.deregister.username }
    } else {
      throw new FatalError('deregister did not return any result.')
    }
  }

  public async getEntitlements(): Promise<EntitlementsConsumption> {
    if (!(await this.sudoUserClient.isSignedIn())) {
      throw new NotSignedInError()
    }

    let result
    try {
      result = await this.client.query<GetEntitlementsForSvsQuery>({
        query: GetEntitlementsForSvsDocument,
        fetchPolicy: 'no-cache',
      })
    } catch (err) {
      if (isAppSyncNetworkError(err)) {
        throw mapNetworkErrorToClientError(err)
      }

      const error = err.graphQLErrors?.[0]
      if (error) {
        throw this.graphQLErrorsToClientError(error)
      } else {
        throw new UnknownGraphQLError(error)
      }
    }

    const error = result.errors?.[0]
    if (error) {
      throw this.graphQLErrorsToClientError(error)
    }

    if (result.data) {
      return result.data.getEntitlementsForSvs
    } else {
      throw new FatalError('getVault did not return any result.')
    }
  }

  public reset(): void {
    this.client.clearStore()
    this.client = this.client = this.createAppSyncClient(
      this.graphqlUrl,
      this.region,
      this.sudoUserClient,
    )
  }

  private createAppSyncClient(
    url: string,
    region: string,
    sudoUserClient: SudoUserClient,
    link?: ApolloLink,
  ): AWSAppSyncClient<NormalizedCacheObject> {
    const clientOptions = {
      url,
      region,
      auth: {
        type: AUTH_TYPE.AMAZON_COGNITO_USER_POOLS,
        jwtToken: async () => await sudoUserClient.getLatestAuthToken(),
      },
    } as const

    // The default AppSync link retries for ~10 minutes on network errors.
    // However, we want to surface these errors to the caller.
    // Since the default AppSync link is not very configurable, we have to
    // create a custom link that just supports GraphQL subscriptions + HTTP.
    // See https://github.com/awslabs/aws-mobile-appsync-sdk-js/blob/b9920f7404/packages/aws-appsync/src/client.ts#L84
    const customLink =
      link ??
      ApolloLink.from([
        new AuthLink(clientOptions),
        createSubscriptionHandshakeLink(
          clientOptions,
          createHttpLink({ uri: clientOptions.url }),
        ),
      ])

    return new AWSAppSyncClient(
      {
        ...clientOptions,
        disableOffline: true,
      },
      {
        link: customLink,
      },
    )
  }

  // private graphQLClientErrorToClientError(error: Error): Error {
  //   const graphQLError = error.graphQLErrors?.[0]
  // }

  private graphQLErrorsToClientError(error: AppSyncError): Error {
    this.logger.error('GraphQL error', { error })

    if (error.errorType === 'DynamoDB:ConditionalCheckFailedException') {
      return new VersionMismatchError()
    } else if (error.errorType === 'sudoplatform.ServiceError') {
      return new ServiceError(error.message)
    } else if (
      error.errorType === 'sudoplatform.vault.InvalidOwnershipProofError'
    ) {
      return new InvalidOwnershipProofError()
    } else if (
      error.errorType === 'sudoplatform.vault.TokenValidationError' ||
      error.errorType === 'sudoplatform.vault.NotAuthorizedError'
    ) {
      return new NotAuthorizedError()
    } else if (
      error.errorType === 'sudoplatform.InsufficientEntitlementsError'
    ) {
      return new InsufficientEntitlementsError()
    } else if (error.errorType === 'sudoplatform.LimitExceededError') {
      return new LimitExceededError()
    } else {
      return new UnknownGraphQLError(error)
    }
  }

  private networkErrorToClientError(error: Error): Error {
    this.logger.error('Network or server error', { error })

    if (error.name === 'ServerError') {
      const serverError = error as ServerError
      if (serverError.statusCode === 401) {
        return new NotAuthorizedError()
      }
    }

    return new FatalError('')
  }
}
