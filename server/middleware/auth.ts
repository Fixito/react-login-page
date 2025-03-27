import { NextFunction, Request, Response } from "express";
import { prisma } from "../db/prisma.js";
import { UnauthorizedError } from "../errors/index.js";

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const token = req.cookies.session;

  if (!token) {
    throw new UnauthorizedError("Authentication required");
  }

  const session = await prisma.session.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!session) {
    res.clearCookie("session");
    throw new UnauthorizedError("Invalid session");
  }

  if (session.expiresAt < new Date()) {
    await prisma.session.delete({ where: { id: session.id } });
    res.clearCookie("session");
    throw new UnauthorizedError("Session expired");
  }

  req.user = {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name,
  };
  req.session = {
    id: session.id,
    token: session.token,
  };

  next();
}
