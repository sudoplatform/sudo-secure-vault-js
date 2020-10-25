import * as t from 'io-ts'

export const Config = t.type({
  region: t.string,
  poolId: t.string,
  clientId: t.string,
  apiUrl: t.string,
  pbkdfRounds: t.number,
})

export type Config = t.TypeOf<typeof Config>
