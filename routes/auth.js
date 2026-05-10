const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { validateInput } = require('../utils/validation');

const router = express.Router();

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
    const user = await User.create({ userId: sanitizedUserId, passwordHash });

    return res.status(201).json({
      message: 'Account created successfully',
      userId: user.userId,
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

    // Generate JWT token with explicit algorithm
    const token = jwt.sign(
      { sub: user._id.toString(), userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '1h', algorithm: 'HS256' } // Shorter expiry (1 hour)
    );

    return res.status(200).json({
      token,
      userId: user.userId,
      expiresIn: 3600,
    });
  } catch (error) {
    next(error);
  }
});

// Optional: Token refresh endpoint
router.post('/refresh', (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(401).json({ error: 'Token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    const newToken = jwt.sign(
      { sub: decoded.sub, userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: '1h', algorithm: 'HS256' }
    );

    return res.json({ token: newToken, expiresIn: 3600 });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

module.exports = router;
