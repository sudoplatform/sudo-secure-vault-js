import {
  CognitoUserAttribute,
  CognitoUserPool,
  AuthenticationDetails,
  CognitoUser,
  CognitoUserSession,
} from 'amazon-cognito-identity-js'
import {
  NotSignedInError,
  UserNotConfirmedError,
  FatalError,
  NotAuthorizedError,
} from '../global/error'

/**
 * Authentication tokens.
 */
export interface AuthenticationTokens {
  idToken: string
  accessToken: string
}

/**
 * Client to use to interact with Secure Vault Authentication Provider.
 */
export class AuthClient {
  private userPool: CognitoUserPool
  private user?: CognitoUser
  private userSession?: CognitoUserSession

  public constructor(userPoolId: string, userPoolCilentId: string) {
    const poolData = {
      UserPoolId: userPoolId,
      ClientId: userPoolCilentId,
    }
    this.userPool = new CognitoUserPool(poolData)
  }

  public async register(
    username: string,
    password: string,
    idToken: string,
    authenticationSalt: string,
    encryptionSalt: string,
    pbkdfRounds: number,
  ): Promise<string> {
    return new Promise((resolve, reject) =>
      this.userPool.signUp(
        username,
        password,
        [],
        [
          new CognitoUserAttribute({ Name: 'idToken', Value: idToken }),
          new CognitoUserAttribute({
            Name: 'authenticationSalt',
            Value: authenticationSalt,
          }),
          new CognitoUserAttribute({
            Name: 'encryptionSalt',
            Value: encryptionSalt,
          }),
          new CognitoUserAttribute({
            Name: 'pbkdfRounds',
            Value: `${pbkdfRounds}`,
          }),
        ],
        (error, result) => {
          if (error) {
            if (
              error.message.includes(
                'sudoplatform.vault.InvalidUsernameError',
              ) ||
              error.message.includes('sudoplatform.vault.TokenValidationError')
            ) {
              reject(new NotAuthorizedError())
            } else {
              reject(error)
            }
            return
          }
          if (result?.userConfirmed) {
            resolve(username)
          } else {
            reject(new UserNotConfirmedError())
          }
        },
      ),
    )
  }

  public async signIn(
    username: string,
    password: string,
  ): Promise<AuthenticationTokens> {
    const user = new CognitoUser({
      Username: username,
      Pool: this.userPool,
    })

    const authenticationDetails = new AuthenticationDetails({
      Username: username,
      Password: password,
    })

    return new Promise((resolve, reject) =>
      user.authenticateUser(authenticationDetails, {
        onSuccess: (userSession) => {
          this.userSession = userSession
          this.user = user
          resolve({
            idToken: userSession.getIdToken().getJwtToken(),
            accessToken: userSession.getAccessToken().getJwtToken(),
          })
        },
        onFailure: (error) => {
          if (error.code === 'NotAuthorizedException')
            reject(new NotAuthorizedError())
          else reject(error)
        },
      }),
    )
  }

  public async refreshTokens(): Promise<AuthenticationTokens> {
    const user = this.userPool.getCurrentUser()
    const refreshToken = this.userSession?.getRefreshToken()
    if (user && refreshToken) {
      return new Promise((resolve, reject) =>
        user.refreshSession(
          refreshToken,
          (error, userSession: CognitoUserSession) => {
            if (error) {
              // TODO: Add error handling for some specific error cases.
              reject(error)
              return
            }
            resolve({
              idToken: userSession.getIdToken().getJwtToken(),
              accessToken: userSession.getAccessToken().getJwtToken(),
            })
          },
        ),
      )
    } else {
      throw new NotSignedInError()
    }
  }

  public async changePassword(
    username: string,
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    await this.signIn(username, oldPassword)
    const user = this.user
    if (user) {
      return new Promise((resolve, reject) =>
        user.changePassword(oldPassword, newPassword, (error) => {
          if (error) {
            if (error.name === 'NotAuthorizedException')
              reject(new NotAuthorizedError())
            else reject(error)
            return
          }
          resolve()
        }),
      )
    } else {
      throw new FatalError(
        'Unable to obtain the current user despite of signing in successfully.',
      )
    }
  }
}
