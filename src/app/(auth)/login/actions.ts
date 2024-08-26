import { loginSchema, LoginValues } from "@/lib/validation";
import { redirect } from "next/navigation";
import { verify } from "@node-rs/argon2";
import prisma from "@/lib/prisma";
import { isRedirectError } from "next/dist/client/components/redirect";
import { lucia } from "@/auth";
import { cookies } from "next/headers";

export async function login(
  credentials: LoginValues,
): Promise<{ error: string }> {
  try {
    const { username, password } = loginSchema.parse(credentials);

    const existingUser = await prisma.user.findFirst({
      where: {
        username: {
          equals: username,
          mode: "insensitive",
        },
      },
    });

    if (!existingUser || !existingUser.passwordHash) {
      return { error: "Username & password is incorrect" };
    }

    const validPassword = await verify(existingUser.passwordHash, password, {
      memoryCost: 1945,
      timeCost: 2,
      outputLen: 32,
      parallelism: 1,
    });

    if (!validPassword) {
      return { error: "Username & password is incorrect" };
    }

    const session = await lucia.createSession(existingUser.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    cookies().set(
      sessionCookie.name,
      sessionCookie.value,
      sessionCookie.attributes,
    );

    return redirect("/");
  } catch (error) {
    if (isRedirectError(error)) throw error;
    console.log(error);
    return { error: "An error occurred while signing up" };
  }
}
