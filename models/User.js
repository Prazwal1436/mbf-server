const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    userId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 50,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isApproved: {
      type: Boolean,
      default: false,
    },
    approvedAt: {
      type: Date,
      default: null,
    },
    approvedByUserId: {
      type: String,
      default: null,
    },
    activeAuthTokenId: {
      type: String,
      default: null,
    },
    authSessionExpiresAt: {
      type: Date,
      default: null,
    },
    activeSessionId: {
      type: String,
      default: null,
    },
    sessionStartTime: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('User', userSchema);
