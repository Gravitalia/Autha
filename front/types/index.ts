export interface User {
  vanity: string;
  username: string;
  avatar: string | null;
  bio: string | null;
  email: string | null;
  verified: boolean;
  // deleted: boolean;
  flags: number;
}

export interface Error {
  message: string;
  error: boolean;
}

export interface TokenResponse {
  vanity: string;
  token: string;
  user_settings: {
    locale: string;
  };
}
