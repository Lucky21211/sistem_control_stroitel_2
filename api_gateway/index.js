// api_gateway/index.js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const expressPino = require('express-pino-logger');

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const expressLogger = expressPino({ logger });

const app = express();
const PORT = process.env.GATEWAY_PORT || 3000;

// Middleware
app.use(express.json());
app.use(expressLogger);
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests, please try again later.'
    }
  }
});
app.use(limiter);

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Access token required'
      }
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Invalid or expired token'
        }
      });
    }
    req.user = user;
    next();
  });
};

// Add X-Request-ID middleware
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || require('crypto').randomUUID();
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
});

// Proxy configuration
const usersServiceProxy = createProxyMiddleware({
  target: process.env.USERS_SERVICE_URL || 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: {
    '^/v1/users': '/v1',
  },
  onProxyReq: (proxyReq, req) => {
    if (req.user) {
      proxyReq.setHeader('X-User-Id', req.user.userId);
      proxyReq.setHeader('X-User-Roles', JSON.stringify(req.user.roles));
    }
  },
  logger
});

const ordersServiceProxy = createProxyMiddleware({
  target: process.env.ORDERS_SERVICE_URL || 'http://localhost:3002',
  changeOrigin: true,
  pathRewrite: {
    '^/v1/orders': '/v1',
  },
  onProxyReq: (proxyReq, req) => {
    if (req.user) {
      proxyReq.setHeader('X-User-Id', req.user.userId);
      proxyReq.setHeader('X-User-Roles', JSON.stringify(req.user.roles));
    }
  },
  logger
});

// Public routes (no authentication)
app.use('/v1/auth', usersServiceProxy);

// Protected routes
app.use('/v1/users', authenticateToken, usersServiceProxy);
app.use('/v1/orders', authenticateToken, ordersServiceProxy);

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    data: {
      service: 'api-gateway',
      status: 'healthy',
      timestamp: new Date().toISOString()
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'Route not found'
    }
  });
});

// Error handler
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Something went wrong'
    }
  });
});

app.listen(PORT, () => {
  logger.info(`API Gateway running on port ${PORT}`);
});