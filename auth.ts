import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { User } from './app/lib/definitions';
import { sql } from '@vercel/postgres';
import bcrpyt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      credentials: {
        email: {
          type: "email",
          label: "Email",
          placeholder: "Enter email",
        },
        password: {
          type: "password",
          label: "Password",
          placeholder: "Enter password",
        },
      },
      authorize: async (credentials) => {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        
        const {email, password} = parsedCredentials.success ? parsedCredentials.data : {email: null, password: null};
        const user = await getUser(email!);

        if (!user)
          throw new Error('User not found');

        const passwordsMatch = await bcrpyt.compare(password!, user.password);

        if (!passwordsMatch)
          throw new Error("Invalid password.");

        console.log("Sign in successful!");
        return user;
      },
    }),
  ],
});
