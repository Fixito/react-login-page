import dotenv from "dotenv";
import express from "express";
import "express-async-errors";
import path from "node:path";
dotenv.config();

import cookieParser from "cookie-parser";
import { StatusCodes } from "http-status-codes";
import { requireAuth } from "./middleware/auth.js";
import { errorHandler } from "./middleware/error-handler.js";
import { notFound } from "./middleware/not-found.js";
import authRoutes from './routes/auth.js';

console.log(`NODE_ENV: ${process.env.NODE_ENV}`);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cookieParser())
app.use(express.json());

// API routes
app.use("/api", (req, _res, next) => {
  console.log(`API Request: ${req.method} ${req.url}`);
  next();
});

// Public routes
app.use('/api/auth', requireAuth, authRoutes);

app.get("/api/health", (_req, res) => {
  res.status(StatusCodes.OK).json({ status: "OK" });
});

if (process.env.NODE_ENV === "production") {
  // Production: Serve static files
  app.use(express.static(path.join(__dirname, "../dist")));

  // Handle React routing in production
  app.get("*", (req, res) => {
    if (!req.path.startsWith("/api")) {
      res
        .status(StatusCodes.OK)
        .sendFile(path.join(__dirname, "../dist/index.html"));
    }
  });
}

app.use(notFound);
app.use(errorHandler);

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

