import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { Router } from 'express';
import { z, ZodError } from 'zod';

import { StatusCodes } from 'http-status-codes';
import { prisma } from '../db/prisma.js';
import { UnauthorizedError } from '../errors/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router()

const signUpSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  name: z.string().optional(),
})

// Sign up
router.post('/signup', async (req, res) => {
  const result = signUpSchema.safeParse(req.body);

  if (!result.success) {
    throw new ZodError(result.error.errors)
  }

  const { email, password, name } = result.data

  // Check if user exists
  const existingUser = await prisma.user.findUnique({
    where: { email },
  })

  if (existingUser) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'Email already registered' })
    return
  }

  // Hash password
  const salt = await bcrypt.genSalt(10)
  const passwordHash = await bcrypt.hash(password, salt)

  // Create user
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      name,
    },
  })

  // Create session
  const token = randomBytes(32).toString('hex')
  const expiresAt = new Date()
  expiresAt.setDate(expiresAt.getDate() + 30) // 30 days from now

  await prisma.session.create({
    data: {
      token,
      userId: user.id,
      expiresAt,
    },
  })

  // Set cookie
  res.cookie('session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    expires: expiresAt,
  })

  res.status(StatusCodes.CREATED).json({
    id: user.id,
    email: user.email,
    name: user.name,
  })
})

const signInSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

// Sign in
router.post('/signin', async (req, res) => {
  const result = signInSchema.safeParse(req.body)

  if (!result.success) {
    throw new ZodError(result.error.errors)
  }

  const { email, password } = result.data

  // Find user
  const user = await prisma.user.findUnique({
    where: { email },
  })

  if (!user) {
    throw new UnauthorizedError('Invalid credentials')
  }

  // Verify password
  const isValid = await bcrypt.compare(password, user.passwordHash)

  if (!isValid) {
    throw new UnauthorizedError('Invalid credentials')
  }

  // Create session
  const token = randomBytes(32).toString('hex')
  const expiresAt = new Date()
  expiresAt.setDate(expiresAt.getDate() + 30) // 30 days from now

  await prisma.session.create({
    data: {
      token,
      userId: user.id,
      expiresAt,
    },
  })

  // Set cookie
  res.cookie('session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    expires: expiresAt,
  })

  res.status(StatusCodes.OK).json({
    id: user.id,
    email: user.email,
    name: user.name,
  })
});

// Sign out
router.post('/signout', requireAuth, async (req, res) => {
  const token = req.cookies.session

  if (token) {
    await prisma.session.delete({
      where: { token },
    })
    res.clearCookie('session')
  }

  res.status(StatusCodes.OK).json({ message: 'Signed out successfully' })
})

// Get current user
router.get('/me', requireAuth, async (req, res) => {
  const user = req.user

  if (!user) {
    throw new UnauthorizedError('Not authenticated')
  }

  res.status(StatusCodes.OK).json({
    id: user.id,
    email: user.email,
    name: user.name,
  })
})

export default router;