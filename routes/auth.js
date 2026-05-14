// Admin can disapprove (revoke approval) of any user
router.post(
  '/admin/users/:userId/disapprove',
  verifyToken,
  verifyAdmin,
  verifyApiKey,
  async (req, res, next) => {
    try {
      const sanitizedUserId = validateInput(req.params.userId, 'userId');
      if (!sanitizedUserId) {
        return res.status(400).json({ error: 'Invalid userId format' });
      }

      const user = await User.findOne({ userId: sanitizedUserId });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      user.isApproved = false;
      user.approvedAt = null;
      user.approvedByUserId = req.user.userId;
      await user.save();

      return res.status(200).json({
        message: 'User disapproved successfully',
        user: {
          userId: user.userId,
          isApproved: user.isApproved,
          approvedAt: user.approvedAt,
          approvedByUserId: user.approvedByUserId,
          isAdmin: user.isAdmin,
        },
      });
    } catch (error) {
      next(error);
    }
  }
);
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { validateInput } = require('../utils/validation');
const { verifyApiKey } = require('../middleware');
const crypto = require('crypto');

const router = express.Router();
const AUTH_TOKEN_LIFETIME_SECONDS = 3600;
const AUTH_TOKEN_LIFETIME_MS = AUTH_TOKEN_LIFETIME_SECONDS * 1000;

const adminUserIds = new Set(
  (process.env.ADMIN_USER_IDS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
);

const isBootstrapAdmin = (userId) => adminUserIds.has(userId);

const clearAuthSession = async (user) => {
  user.activeAuthTokenId = null;
  user.authSessionExpiresAt = null;
  await user.save();
};

const clearAuthSessionIfExpired = async (user) => {
  if (
    user.activeAuthTokenId &&
    user.authSessionExpiresAt &&
    user.authSessionExpiresAt.getTime() <= Date.now()
  ) {
    await clearAuthSession(user);
  }
};

const verifyAdmin = (req, res, next) => {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  next();
};

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    const user = await User.findOne({ userId: decoded.userId });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    await clearAuthSessionIfExpired(user);

    if (
      !decoded.jti ||
      user.activeAuthTokenId == null ||
      user.authSessionExpiresAt == null ||
      user.activeAuthTokenId !== decoded.jti
    ) {
      return res.status(401).json({ error: 'Session is no longer active' });
    }

    req.userId = decoded.userId;
    req.sub = decoded.sub;
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};


// Password requirements
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

router.post('/register', async (req, res, next) => {
  try {
    const { userId, password } = req.body;

    // Input validation
    if (!userId || !password) {
      return res.status(400).json({ error: 'userId and password are required' });
    }

    // Sanitize and validate userId
    const sanitizedUserId = validateInput(userId, 'userId');
    if (!sanitizedUserId) {
      return res.status(400).json({ error: 'Invalid userId format' });
    }

    // Validate password strength
    if (password.length < PASSWORD_MIN_LENGTH) {
      return res.status(400).json({
        error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters`,
      });
    }

    if (!PASSWORD_REGEX.test(password)) {
      return res.status(400).json({
        error: 'Password must contain uppercase, lowercase, number, and special character',
      });
    }

    // Check if user already exists
    const existing = await User.findOne({ userId: sanitizedUserId });
    if (existing) {
      return res.status(409).json({ error: 'User ID already exists' });
    }

    // Hash password with bcrypt
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const bootstrapAdmin = isBootstrapAdmin(sanitizedUserId);
    const user = await User.create({
      userId: sanitizedUserId,
      passwordHash,
      isAdmin: bootstrapAdmin,
      isApproved: bootstrapAdmin,
      approvedAt: bootstrapAdmin ? new Date() : null,
      approvedByUserId: bootstrapAdmin ? sanitizedUserId : null,
    });

    return res.status(201).json({
      message: bootstrapAdmin
        ? 'Admin account created successfully'
        : 'Account created successfully. Awaiting admin approval.',
      userId: user.userId,
      isApproved: user.isApproved,
    });
  } catch (error) {
    next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { userId, password } = req.body;

    // Input validation
    if (!userId || !password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Sanitize userId
    const sanitizedUserId = validateInput(userId, 'userId');
    if (!sanitizedUserId) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Find user
    const user = await User.findOne({ userId: sanitizedUserId });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare passwords
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.isApproved) {
      return res.status(403).json({
        error: 'Account pending admin approval',
      });
    }

    await clearAuthSessionIfExpired(user);

    if (user.activeAuthTokenId && user.authSessionExpiresAt) {
      return res.status(409).json({
        error: 'This account is already logged in on another device',
      });
    }

    const tokenId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + AUTH_TOKEN_LIFETIME_MS);

    user.activeAuthTokenId = tokenId;
    user.authSessionExpiresAt = expiresAt;
    await user.save();

    // Generate JWT token with explicit algorithm
    const token = jwt.sign(
      { sub: user._id.toString(), userId: user.userId, jti: tokenId },
      process.env.JWT_SECRET,
      { expiresIn: '1h', algorithm: 'HS256' }
    );

    return res.status(200).json({
      token,
      userId: user.userId,
      isAdmin: user.isAdmin,
      expiresIn: AUTH_TOKEN_LIFETIME_SECONDS,
    });
  } catch (error) {
    next(error);
  }
});

// Optional: Token refresh endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(401).json({ error: 'Token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    const user = await User.findOne({ userId: decoded.userId });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    await clearAuthSessionIfExpired(user);

    if (
      !decoded.jti ||
      user.activeAuthTokenId == null ||
      user.authSessionExpiresAt == null ||
      user.activeAuthTokenId !== decoded.jti
    ) {
      return res.status(401).json({ error: 'Session is no longer active' });
    }

    user.authSessionExpiresAt = new Date(Date.now() + AUTH_TOKEN_LIFETIME_MS);
    await user.save();

    const newToken = jwt.sign(
      { sub: decoded.sub, userId: decoded.userId, jti: decoded.jti },
      process.env.JWT_SECRET,
      { expiresIn: '1h', algorithm: 'HS256' }
    );

    return res.json({ token: newToken, expiresIn: AUTH_TOKEN_LIFETIME_SECONDS });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

router.post('/logout', verifyToken, async (req, res, next) => {
  try {
    req.user.activeSessionId = null;
    req.user.sessionStartTime = null;
    req.user.activeAuthTokenId = null;
    req.user.authSessionExpiresAt = null;
    await req.user.save();

    return res.status(200).json({
      message: 'Logged out successfully',
    });
  } catch (error) {
    next(error);
  }
});

// Now requires API key in header for admin access
router.get('/admin/users', verifyToken, verifyAdmin, verifyApiKey, async (req, res, next) => {
  try {
    const status = req.query.status;
    const filter = {};

    if (status === 'pending') {
      filter.isApproved = false;
    } else if (status === 'approved') {
      filter.isApproved = true;
    }

    const users = await User.find(filter)
      .sort({ createdAt: -1 })
      .select(
        'userId isAdmin isApproved approvedAt approvedByUserId createdAt updatedAt'
      )
      .lean();

    return res.status(200).json({ users });
  } catch (error) {
    next(error);
  }
});

router.post(
  '/admin/users/:userId/approve',
  verifyToken,
  verifyAdmin,
  verifyApiKey,
  async (req, res, next) => {
    try {
      const sanitizedUserId = validateInput(req.params.userId, 'userId');
      if (!sanitizedUserId) {
        return res.status(400).json({ error: 'Invalid userId format' });
      }

      const user = await User.findOne({ userId: sanitizedUserId });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      user.isApproved = true;
      user.approvedAt = new Date();
      user.approvedByUserId = req.user.userId;
      await user.save();

      return res.status(200).json({
        message: 'User approved successfully',
        user: {
          userId: user.userId,
          isApproved: user.isApproved,
          approvedAt: user.approvedAt,
          approvedByUserId: user.approvedByUserId,
          isAdmin: user.isAdmin,
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

// Start mock location session (only one per user)
router.post('/start-mock-session', verifyToken, async (req, res, next) => {
  try {
    const user = await User.findOne({ userId: req.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user already has an active session
    if (user.activeSessionId) {
      return res.status(409).json({
        error: 'Another device is already using mock location for this user',
        activeSessionId: user.activeSessionId,
      });
    }

    // Generate unique session ID
    const sessionId = crypto.randomUUID();

    // Store session
    user.activeSessionId = sessionId;
    user.sessionStartTime = new Date();
    await user.save();

    return res.status(200).json({
      sessionId,
      message: 'Mock location session started',
    });
  } catch (error) {
    next(error);
  }
});

// End mock location session
router.post('/end-mock-session', verifyToken, async (req, res, next) => {
  try {
    const { sessionId } = req.body;
    if (!sessionId) {
      return res.status(400).json({ error: 'sessionId is required' });
    }

    const user = await User.findOne({ userId: req.userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify session ownership
    if (user.activeSessionId !== sessionId) {
      return res.status(403).json({
        error: 'Session ID does not match current session',
      });
    }

    // Clear session
    user.activeSessionId = null;
    user.sessionStartTime = null;
    await user.save();

    return res.status(200).json({
      message: 'Mock location session ended',
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
