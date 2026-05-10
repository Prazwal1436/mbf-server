/**
 * Validate and sanitize userId input
 * @param {string} input - The input to validate
 * @param {string} type - Type of input (userId, etc.)
 * @returns {string|null} - Sanitized input or null if invalid
 */
function validateInput(input, type = 'userId') {
  if (typeof input !== 'string') {
    return null;
  }

  const trimmed = input.trim();

  // Basic validation rules
  if (type === 'userId') {
    // Allow alphanumeric, underscore, hyphen only
    // Length: 3-50 characters
    if (!/^[a-zA-Z0-9_-]{3,50}$/.test(trimmed)) {
      return null;
    }
  }

  return trimmed;
}

/**
 * Sanitize string to prevent XSS
 * @param {string} str - String to sanitize
 * @returns {string} - Sanitized string
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  
  return str
    .replace(/[<>\"']/g, (char) => {
      const map = { '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
      return map[char];
    })
    .trim();
}

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean}
 */
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

module.exports = {
  validateInput,
  sanitizeString,
  validateEmail,
};
