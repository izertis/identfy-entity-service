import { BACKEND } from "../../../shared/config/configuration";
import { join as joinPath } from 'node:path/posix';
import fetch from 'node-fetch';

export interface AuthLogin {
  refresh: string;
  access: string;
  user_id: number;
  username: string;
  email: string;
}

export async function authBackend(): Promise<string> {
  const url = new URL(BACKEND.url);
  url.pathname = joinPath("/api/api-token-auth")
  const body = {
    "username": BACKEND.user,
    "password": BACKEND.pass
  };
  const response = await fetch(url.toString(), {
    method: 'POST',
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  const data = await response.json() as AuthLogin;
  return data.access;
}
