import { Request, Response } from "express";
import { StatusCodes } from "http-status-codes";

export function notFound(req: Request, res: Response) {
  res.status(StatusCodes.NOT_FOUND).json({ error: `${req.path} Not Found` });
}
