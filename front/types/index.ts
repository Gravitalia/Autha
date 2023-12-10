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
