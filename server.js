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
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET', 'ADMIN_API_KEY', 'ALLOWED_ORIGINS'];
const missingVars = requiredEnvVars.filter((v) => !process.env[v]);
if (missingVars.length > 0) {
  console.error(`\n✗ Missing required env vars: ${missingVars.join(', ')}`);
  process.exit(1);
}

// JWT_SECRET should be at least 32 characters
if (process.env.JWT_SECRET.length < 32) {
  console.warn('Warning: JWT_SECRET is too short. Use at least 32 characters.');
}
if (process.env.ADMIN_API_KEY.length < 12) {
  console.warn('Warning: ADMIN_API_KEY is too short. Use at least 12 characters.');
}
if (!process.env.ALLOWED_ORIGINS) {
  console.warn('Warning: ALLOWED_ORIGINS is not set. Defaulting to http://localhost:3000');
}

// Security middleware
app.use(helmet());

// CORS configuration (allow all headers and log for debugging)
const corsOptions = {
  origin: (origin, callback) => {
    const allowed = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`Blocked CORS request from: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-requested-with', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Type', 'Authorization'],
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

async function connectWithRetry(retries = 5, delay = 3000) {
  for (let i = 0; i < retries; i++) {
    try {
      await mongoose.connect(process.env.MONGODB_URI, {
        retryWrites: true,
        w: 'majority',
      });
      console.log('Connected to MongoDB');
      return;
    } catch (error) {
      console.error(`\n✗ MongoDB connection failed (attempt ${i + 1}/${retries}):`, error.message);
      if (i < retries - 1) {
        console.log(`Retrying in ${delay / 1000} seconds...`);
        await new Promise((res) => setTimeout(res, delay));
      } else {
        console.error('✗ Could not connect to MongoDB after multiple attempts. Exiting.');
        process.exit(1);
      }
    }
  }
}

async function start() {
  let server;
  await connectWithRetry();
  try {
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

// Global error handlers
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Optionally exit: process.exit(1);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception thrown:', err);
  process.exit(1);
});

start();
