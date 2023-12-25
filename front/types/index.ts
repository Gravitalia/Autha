/**
 * User structure used to know who is connected.
 */
export interface User {
  /** @default "" */
  vanity: string;
  /** @default "" */
  username: string;
  /** @default null */
  avatar: string | null;
  /** @default null */
  bio: string | null;
  /** @default null */
  email: string | null;
  /** @default false */
  verified: boolean;
  /** @default false */
  deleted: boolean;
  /** @default 0 */
  flags: number;
}

/**
 * API error messages.
 */
export interface Error {
  /**
   * Error message containing informations to handle it.
   */
  message: string;
  error: boolean;
}

/**
 * API response on login or account creation.
 */
export interface TokenResponse {
  vanity: string;
  token: string;
  user_settings: {
    locale: string;
  };
}
