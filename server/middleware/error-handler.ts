import { NextFunction, Request, Response } from "express";
import { StatusCodes } from "http-status-codes";
import { ZodError } from "zod";

interface CustomError extends Error {
  statusCode?: number;
}

export const errorHandler = (
  err: CustomError,
  _req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error(err);

  if (err instanceof ZodError) {
    res.status(StatusCodes.BAD_REQUEST).json({
      error: 'Validation failed',
      details: err.errors.map((err) => ({
        path: err.path.join('.'),
        message: err.message,
      })),
    })
    return
  }

  const statusCode = err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR;
  const message = err.message || "Internal server error";


  res.status(statusCode).json({ error: message });
  next()
}
