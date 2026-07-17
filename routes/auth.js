

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { verifyToken, verifyApiKey } = require('../middleware');
const { validateInput } = require('../utils/validation');
const User = require('../models/User');
const bcrypt = require('bcryptjs');


// --- Utility and Middleware Definitions (must be above all usages) ---
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

const allowBootstrapOrAdmin = async (req, res, next) => {
  try {
    const sanitizedUserId = validateInput(req.body?.userId, 'userId');
    const hasUsers = await User.exists({});
    const isBootstrapRegistration =
      !hasUsers && sanitizedUserId && isBootstrapAdmin(sanitizedUserId);

    if (isBootstrapRegistration) {
      return verifyApiKey(req, res, () => {
        req.isBootstrapRegistration = true;
        next();
      });
    }

    return verifyToken(req, res, () =>
      verifyAdmin(req, res, () => verifyApiKey(req, res, next))
    );
  } catch (error) {
    return next(error);
  }
};

// --- Route Definitions ---

// Admin: Clear session for any user
router.post(
  '/admin/users/:userId/clear-session',
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
      user.activeAuthTokenId = null;
      user.authSessionExpiresAt = null;
      user.activeSessionId = null;
      user.sessionStartTime = null;
      await user.save();
      return res.status(200).json({ message: 'Session cleared', userId: user.userId });
    } catch (error) {
      next(error);
    }
  }
);

// ...existing code...

// Admin: Reset password for any user
router.post(
  '/admin/users/:userId/reset-password',
  verifyToken,
  verifyAdmin,
  verifyApiKey,
  async (req, res, next) => {
    try {
      const sanitizedUserId = validateInput(req.params.userId, 'userId');
      const { newPassword } = req.body;
      if (!sanitizedUserId || !newPassword) {
        return res.status(400).json({ error: 'Invalid userId or password' });
      }
      // Password strength check (reuse from register)
      const PASSWORD_MIN_LENGTH = 8;
      const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (newPassword.length < PASSWORD_MIN_LENGTH) {
        return res.status(400).json({ error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` });
      }
      if (!PASSWORD_REGEX.test(newPassword)) {
        return res.status(400).json({ error: 'Password must contain uppercase, lowercase, number, and special character' });
      }
      const user = await User.findOne({ userId: sanitizedUserId });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      const salt = await bcrypt.genSalt(12);
      user.passwordHash = await bcrypt.hash(newPassword, salt);
      await user.save();
      return res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: Delete any user
router.delete(
  '/admin/users/:userId',
  verifyToken,
  verifyAdmin,
  verifyApiKey,
  async (req, res, next) => {
    try {
      const sanitizedUserId = validateInput(req.params.userId, 'userId');
      if (!sanitizedUserId) {
        return res.status(400).json({ error: 'Invalid userId format' });
      }
      const user = await User.findOneAndDelete({ userId: sanitizedUserId });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.status(200).json({ message: 'User deleted successfully' });
    } catch (error) {
      next(error);
    }
  }
);


// ...all other route definitions...

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
      user.activeAuthTokenId = null;
      user.authSessionExpiresAt = null;
      user.activeSessionId = null;
      user.sessionStartTime = null;
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

// ...existing code...

// ...removed local verifyToken, now using imported version...


// Password requirements
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

router.post('/register', allowBootstrapOrAdmin, async (req, res, next) => {
  try {
    const { userId, password, isAdmin } = req.body;

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

    const isBootstrapRegistration = Boolean(req.isBootstrapRegistration);

    // Admin-managed creation: creator decides whether target account is admin.
    const shouldBeAdmin = isBootstrapRegistration
      ? true
      : Boolean(isAdmin) || isBootstrapAdmin(sanitizedUserId);
    const user = await User.create({
      userId: sanitizedUserId,
      passwordHash,
      isAdmin: shouldBeAdmin,
      isApproved: true,
      approvedAt: new Date(),
      approvedByUserId: req.user?.userId || sanitizedUserId,
    });

    return res.status(201).json({
      message: shouldBeAdmin ? 'Admin account created successfully' : 'User account created successfully',
      userId: user.userId,
      isAdmin: user.isAdmin,
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

    // Enforce single active session per user until explicit logout/admin clear
    if (user.activeAuthTokenId) {
      return res.status(403).json({ error: 'User already has an active session. Please logout from other device first.' });
    }

    const tokenId = crypto.randomUUID();

    user.activeAuthTokenId = tokenId;
    user.authSessionExpiresAt = null;
    await user.save();

    // Generate JWT token with explicit algorithm and isAdmin

    const token = jwt.sign(
      { sub: user._id.toString(), userId: user.userId, isAdmin: user.isAdmin, jti: tokenId },
      process.env.JWT_SECRET,
      { algorithm: 'HS256' }
    );

    return res.status(200).json({
      token,
      userId: user.userId,
      isAdmin: user.isAdmin,
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
    const refreshUser = await User.findOne({ userId: decoded.userId });
    if (!refreshUser) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (
      !decoded.jti ||
      refreshUser.activeAuthTokenId == null ||
      refreshUser.activeAuthTokenId !== decoded.jti
    ) {
      return res.status(401).json({ error: 'Session is no longer active' });
    }

    const newToken = jwt.sign(
      {
        sub: refreshUser._id.toString(),
        userId: refreshUser.userId,
        isAdmin: refreshUser.isAdmin,
        jti: decoded.jti,
      },
      process.env.JWT_SECRET,
      { algorithm: 'HS256' }
    );

    return res.json({ token: newToken });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

router.get('/validate', verifyToken, async (req, res, next) => {
  try {
    const userId = req.user?.userId;
    const tokenId = req.user?.jti;

    if (!userId || !tokenId) {
      return res.status(401).json({ error: 'Invalid token payload' });
    }

    const user = await User.findOne({ userId });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (!user.isApproved) {
      return res.status(401).json({ error: 'User is not approved' });
    }

    if (
      !user.activeAuthTokenId ||
      user.activeAuthTokenId !== tokenId
    ) {
      return res.status(401).json({ error: 'Session is no longer active' });
    }

    return res.status(200).json({
      valid: true,
      userId: user.userId,
      isAdmin: user.isAdmin,
    });
  } catch (error) {
    next(error);
  }
});

router.post('/logout', verifyToken, async (req, res, next) => {
  try {
    const userId = req.user?.userId;
    if (userId) {
      const user = await User.findOne({ userId });
      if (user) {
        user.activeSessionId = null;
        user.sessionStartTime = null;
        user.activeAuthTokenId = null;
        user.authSessionExpiresAt = null;
        await user.save();
      }
    }

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
        'userId isAdmin isApproved approvedAt approvedByUserId createdAt updatedAt activeAuthTokenId authSessionExpiresAt'
      )
      .lean();

    // Add 'active' field to each user (active if session exists and not expired, or session has no expiry)
    const now = Date.now();
    const usersWithActive = users.map(u => {
      let active = false;
      if (u.activeAuthTokenId) {
        if (!u.authSessionExpiresAt) {
          active = true;
        } else {
          const expires = new Date(u.authSessionExpiresAt).getTime();
          active = expires > now;
        }
      }
      // Remove session fields from response for privacy
      delete u.activeAuthTokenId;
      delete u.authSessionExpiresAt;
      return { ...u, active };
    });

    return res.status(200).json({ users: usersWithActive });
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

// ...mock location session endpoints removed...

module.exports = router;
