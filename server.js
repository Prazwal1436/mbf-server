require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const { errorHandler, requestLogger } = require('./middleware');

const app = express();
const port = process.env.PORT || 4000;
const nodeEnv = process.env.NODE_ENV || 'development';

// Validate environment variables
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingVars = requiredEnvVars.filter((v) => !process.env[v]);
if (missingVars.length > 0) {
  throw new Error(`Missing required env vars: ${missingVars.join(', ')}`);
}

// JWT_SECRET should be at least 32 characters
if (process.env.JWT_SECRET.length < 32) {
  console.warn('Warning: JWT_SECRET is too short. Use at least 32 characters.');
}

// Security middleware
app.use(helmet());

// CORS configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
};
app.use(cors(corsOptions));

// Request size and parsing limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// Request logging
app.use(requestLogger);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Only 10 requests per 15 minutes for auth
  skipSuccessfulRequests: true,
  message: 'Too many authentication attempts, please try again later.',
});

app.get('/health', (_, res) => {
  res.status(200).json({ status: 'ok' });
});

app.use('/auth', authLimiter, authRoutes);

// 404 handler
app.use((_, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler (must be last)
app.use(errorHandler);

async function start() {
  let server;
  
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI, {
      retryWrites: true,
      w: 'majority',
    });
    console.log('Connected to MongoDB');

    // Start server
    server = app.listen(port, () => {
      console.log(`\n✓ Auth server running on port ${port} [${nodeEnv}]`);
    });
  } catch (error) {
    console.error('\n✗ Failed to start server:', error.message);
    process.exit(1);
  }

  // Graceful shutdown
  const shutdown = async (signal) => {
    console.log(`\n${signal} received, shutting down gracefully...`);
    server?.close(async () => {
      try {
        await mongoose.disconnect();
        console.log('Server closed and MongoDB disconnected');
        process.exit(0);
      } catch (error) {
        console.error('Error during shutdown:', error);
        process.exit(1);
      }
    });
    setTimeout(() => process.exit(1), 10000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start();
