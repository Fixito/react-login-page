import express from "express";
import "express-async-errors";
import path from "node:path";
// import cors from 'cors';
import dotenv from "dotenv";
dotenv.config();

import cookieParser from "cookie-parser";
import { createProxyMiddleware } from "http-proxy-middleware";
import { StatusCodes } from "http-status-codes";
import { errorHandler } from "./middleware/error-handler.js";
import { notFound } from "./middleware/not-found.js";
import authRoutes from './routes/auth.js';

console.log(`NODE_ENV: ${process.env.NODE_ENV}`);

const app = express();
const PORT = process.env.PORT || 3000;
const VITE_PORT = process.env.VITE_PORT || 5173;

// Middleware
// app.use(cors());
app.use(cookieParser())
app.use(express.json());

// API routes
app.use("/api", (req, _res, next) => {
  console.log(`API Request: ${req.method} ${req.url}`);
  next();
});

// Public routes
app.use('/api/auth', authRoutes)

app.get("/api/health", (_req, res) => {
  res.status(StatusCodes.OK).json({ status: "OK" });
});


// Development: Proxy all non-API requests to Vite dev server
if (process.env.NODE_ENV !== "production") {
  app.use(
    "/",
    createProxyMiddleware({
      target: `http://localhost:${VITE_PORT}`,
      changeOrigin: true,
      ws: true,
      // Don't proxy /api requests
      pathFilter: (pathname: string) => !pathname.startsWith("/api"),
    }),
  );
} else {
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

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  if (process.env.NODE_ENV !== "production") {
    console.log(`Proxying non-API requests to http://localhost:${VITE_PORT}`);
  }
});
