// api_gateway/index.js 
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const expressPino = require('express-pino-logger');

const logger = pino({ 
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => {
      return { level: label };
    }
  },
  timestamp: () => `,"time":"${new Date().toISOString()}"`
});

const expressLogger = expressPino({ 
  logger,
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      headers: {
        'x-request-id': req.headers['x-request-id'],
        'user-agent': req.headers['user-agent']
      }
    }),
    res: (res) => ({
      statusCode: res.statusCode
    })
  }
});

const app = express();
const PORT = process.env.GATEWAY_PORT || 3000;

// Middleware
app.use(express.json());
app.use(expressLogger);
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  credentials: true
}));

// Rate limiting - разные лимиты для разных endpoint-ов
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 попыток входа/регистрации
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many authentication attempts, please try again later.'
    }
  },
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 запросов для API
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests, please try again later.'
    }
  }
});

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  // Публичные пути (точно по ТЗ)
  const publicPaths = ['/v1/auth/register', '/v1/auth/login', '/health'];
  if (publicPaths.some(path => req.path.startsWith(path))) {
    return next();
  }

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

// Add X-Request-ID middleware (трассировка по ТЗ)
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || require('crypto').randomUUID();
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);
  
  // Добавляем requestId ко всем логам
  req.log = logger.child({ requestId });
  next();
});

// Proxy configuration with enhanced logging
const createServiceProxy = (serviceName, target, pathRewrite) => {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    pathRewrite,
    onProxyReq: (proxyReq, req) => {
      // Прокидываем пользовательские заголовки вглубь (по ТЗ)
      if (req.user) {
        proxyReq.setHeader('X-User-Id', req.user.userId);
        proxyReq.setHeader('X-User-Roles', JSON.stringify(req.user.roles));
        proxyReq.setHeader('X-User-Email', req.user.email);
      }
      
      // Логируем проксирование
      req.log.info(`Proxying to ${serviceName}: ${req.method} ${req.path}`);
    },
    onProxyRes: (proxyRes, req, res) => {
      req.log.info(`Response from ${serviceName}: ${proxyRes.statusCode}`);
    },
    onError: (err, req, res) => {
      req.log.error(`Proxy error to ${serviceName}:`, err);
      res.status(503).json({
        success: false,
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: `${serviceName} is temporarily unavailable`
        }
      });
    }
  });
};

const usersServiceProxy = createServiceProxy(
  'users-service',
  process.env.USERS_SERVICE_URL || 'http://localhost:3001',
  { '^/v1/users': '/v1' }
);

const ordersServiceProxy = createServiceProxy(
  'orders-service', 
  process.env.ORDERS_SERVICE_URL || 'http://localhost:3002',
  { '^/v1/orders': '/v1' }
);

// Apply rate limiting
app.use('/v1/auth', authLimiter);
app.use('/v1', apiLimiter);

// Apply authentication (кроме публичных путей)
app.use(authenticateToken);

// Routes - точное проксирование по ТЗ
app.use('/v1/auth', usersServiceProxy);
app.use('/v1/users', usersServiceProxy);
app.use('/v1/orders', ordersServiceProxy);

// Health check with service status
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    data: {
      service: 'api-gateway',
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    }
  };
  
  req.log.info('Health check passed');
  res.json(health);
});

// 404 handler
app.use('*', (req, res) => {
  req.log.warn(`Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'Route not found'
    }
  });
});

// Global error handler
app.use((err, req, res, next) => {
  req.log.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Something went wrong'
    }
  });
});

app.listen(PORT, () => {
  logger.info(`🚀 API Gateway running on port ${PORT}`);
  logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`🔗 Users Service: ${process.env.USERS_SERVICE_URL}`);
  logger.info(`📦 Orders Service: ${process.env.ORDERS_SERVICE_URL}`);
});