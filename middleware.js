const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 400 ? 'WARN' : 'INFO';
    console.log(
      `[${level}] ${req.method} ${req.path} - ${res.statusCode} ${duration}ms`
    );
  });
  
  next();
};

const errorHandler = (err, req, res, next) => {
  const nodeEnv = process.env.NODE_ENV || 'development';
  
  console.error('[ERROR]', {
    message: err.message,
    stack: nodeEnv === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
  });

  // Don't leak error details in production
  const message = nodeEnv === 'production' ? 'Internal server error' : err.message;
  
  res.status(err.status || 500).json({
    error: message,
    ...(nodeEnv === 'development' && { stack: err.stack }),
  });
};

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }

  const token = authHeader.slice(7);
  try {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { 
      algorithms: ['HS256'] 
    });
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

module.exports = {
  requestLogger,
  errorHandler,
  verifyToken,
};
