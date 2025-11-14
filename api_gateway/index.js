// api_gateway/index.js 
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const expressPino = require('express-pino-logger');

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-2024';

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

// Add X-Request-ID middleware (трассировка по ТЗ)
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || require('crypto').randomUUID();
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);
  
  // Добавляем requestId ко всем логам
  req.log = logger.child({ requestId });
  next();
});

// Apply rate limiting ДО аутентификации
app.use('/v1/auth', authLimiter);
app.use('/v1', apiLimiter);

// Proxy configuration 
const createServiceProxy = (serviceName, target) => {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    // УБИРАЕМ pathRewrite - он ломает запросы!
    onProxyReq: (proxyReq, req, res) => {
      // Прокидываем пользовательские заголовки
      if (req.user) {
        const userId = req.user.userId || req.user.id;
        const userRoles = req.user.roles || ['user'];
        const userEmail = req.user.email || '';
        
        proxyReq.setHeader('X-User-Id', userId);
        proxyReq.setHeader('X-User-Roles', JSON.stringify(userRoles));
        proxyReq.setHeader('X-User-Email', userEmail);
        
        // Логируем для отладки
        console.log('Setting headers for', serviceName, {
          userId,
          roles: userRoles,
          email: userEmail
        });
      } else {
        console.log('No user object for', serviceName);
      }
      
      // Передаем тело запроса (только для POST/PUT/PATCH)
      if (req.body && Object.keys(req.body).length > 0 && 
          (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
      
      console.log(`Proxying to ${serviceName}: ${req.method} ${req.originalUrl}`);
    },
    onProxyRes: (proxyRes, req, res) => {
      console.log(`Response from ${serviceName}: ${proxyRes.statusCode}`);
    },
    onError: (err, req, res) => {
      console.error(`Proxy error to ${serviceName}:`, err);
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

// Создаем прокси БЕЗ pathRewrite (он ломает запросы)
const usersServiceProxy = createServiceProxy(
  'users-service',
  process.env.USERS_SERVICE_URL || 'http://service_users:3001'
);

const ordersServiceProxy = createServiceProxy(
  'orders-service', 
  process.env.ORDERS_SERVICE_URL || 'http://service_orders:3002'
);

// Публичные routes ДО аутентификации
app.use('/v1/auth', usersServiceProxy);

// JWT authentication middleware - ТОЛЬКО для защищенных путей
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('AuthenticateToken called for:', req.method, req.url);
  console.log('Authorization header:', authHeader ? 'PRESENT' : 'MISSING');
  console.log('Token:', token ? `${token.substring(0, 20)}...` : 'MISSING');

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Access token required'
      }
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT verification failed:', err.message);
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Invalid or expired token'
        }
      });
    }
    
    console.log('JWT verification successful. User:', user);
    req.user = user;
    next();
  });
};

// Apply authentication ТОЛЬКО для защищенных путей
app.use('/v1/users', authenticateToken, usersServiceProxy);
app.use('/v1/orders', authenticateToken, ordersServiceProxy);
app.use('/v1/profile', authenticateToken, usersServiceProxy);

// Health check
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
  logger.info(`API Gateway running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Users Service: ${process.env.USERS_SERVICE_URL}`);
  logger.info(`Orders Service: ${process.env.ORDERS_SERVICE_URL}`);
});
