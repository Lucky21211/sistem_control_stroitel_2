const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { createLogger } = require('./middleware/logger');
const tracingMiddleware = require('./middleware/tracing');
const expressPino = require('express-pino-logger');
const { z } = require('zod');

const logger = createLogger('users-service');
const expressLogger = expressPino({ logger });

const app = express();
const PORT = process.env.SERVICE_PORT || 3001;

// Database connection
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'taskdb',
  user: process.env.DB_USER || 'admin',
  password: process.env.DB_PASSWORD || 'password',
});

// Validation schemas
const registerSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  name: z.string().min(2, 'Name must be at least 2 characters')
});

const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required')
});

const updateProfileSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').optional()
});

// CORS middleware
app.use((req, res, next) => {
  const allowedOrigins = ['http://127.0.0.1:5500', 'http://localhost:3000', 'http://localhost:5500', 'http://localhost:3001'];
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  } else {
    res.header('Access-Control-Allow-Origin', '*');
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-ID, X-User-Id, X-User-Roles');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// Middleware
app.use(express.json());
app.use(expressLogger);
app.use(tracingMiddleware);

// Utility functions
const formatResponse = (success, data = null, error = null) => ({
  success,
  data,
  error
});

// Routes
// Register
app.post('/v1/auth/register', async (req, res) => {
  try {
    const validatedData = registerSchema.parse(req.body);
    
    // Проверьте, существует ли пользователь уже сейчас
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [validatedData.email]
    );
    
    if (existingUser.rows.length > 0) {
      req.log.warn(`Registration failed: user already exists - ${validatedData.email}`);
      return res.status(409).json(
        formatResponse(false, null, {
          code: 'USER_EXISTS',
          message: 'User with this email already exists'
        })
      );
    }

    // Хэш-пароль
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(validatedData.password, saltRounds);

    // Создать пользователя
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name) 
       VALUES ($1, $2, $3) 
       RETURNING id, email, name, roles, created_at, updated_at`,
      [validatedData.email, passwordHash, validatedData.name]
    );

    const user = result.rows[0];
    
    req.log.info({ userId: user.id, email: user.email }, 'User registered successfully');
    
    res.status(201).json(
      formatResponse(true, {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles
        }
      })
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      req.log.warn('Registration validation failed', { errors: error.errors });
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error('Registration failed:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Registration failed'
      })
    );
  }
});

// Login
app.post('/v1/auth/login', async (req, res) => {
  try {
    const validatedData = loginSchema.parse(req.body);
    
    
    const result = await pool.query(
      'SELECT id, email, password_hash, name, roles FROM users WHERE email = $1',
      [validatedData.email]
    );
    
    if (result.rows.length === 0) {
      req.log.warn(`Login failed: user not found - ${validatedData.email}`);
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        })
      );
    }
    
    const user = result.rows[0];
    
    // Проверьте пароль
    const isValidPassword = await bcrypt.compare(validatedData.password, user.password_hash);
    
    if (!isValidPassword) {
      req.log.warn(`Login failed: invalid password for user - ${validatedData.email}`);
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        })
      );
    }

    // Generate JWT
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        roles: user.roles
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    req.log.info({ userId: user.id }, 'User logged in successfully');
    
    res.json(
      formatResponse(true, {
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles
        }
      })
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      req.log.warn('Login validation failed', { errors: error.errors });
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error('Login failed:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Login failed'
      })
    );
  }
});

// Получить текущий профиль
app.get('/v1/profile', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    
    if (!userId) {
      req.log.warn('Profile access without user ID');
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'UNAUTHORIZED',
          message: 'User authentication required'
        })
      );
    }
    
    const result = await pool.query(
      'SELECT id, email, name, roles, created_at, updated_at FROM users WHERE id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      req.log.warn(`Profile not found for user ID: ${userId}`);
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'USER_NOT_FOUND',
          message: 'User not found'
        })
      );
    }
    
    const user = result.rows[0];
    
    req.log.debug({ userId }, 'Profile retrieved successfully');
    
    res.json(
      formatResponse(true, { user })
    );
  } catch (error) {
    req.log.error('Failed to get profile:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to get profile'
      })
    );
  }
});


app.put('/v1/profile', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    
    if (!userId) {
      req.log.warn('Profile update without user ID');
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'UNAUTHORIZED',
          message: 'User authentication required'
        })
      );
    }
    
    const validatedData = updateProfileSchema.parse(req.body);
    
    const result = await pool.query(
      'UPDATE users SET name = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, email, name, roles, created_at, updated_at',
      [validatedData.name, userId]
    );
    
    if (result.rows.length === 0) {
      req.log.warn(`Profile update failed: user not found - ${userId}`);
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'USER_NOT_FOUND',
          message: 'User not found'
        })
      );
    }
    
    const user = result.rows[0];
    
    req.log.info({ userId }, 'Profile updated successfully');
    
    res.json(
      formatResponse(true, { user })
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      req.log.warn('Profile update validation failed', { errors: error.errors });
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error('Failed to update profile:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to update profile'
      })
    );
  }
});

// Получить список пользователей (только для администраторов)
app.get('/v1/users', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = JSON.parse(req.headers['x-user-roles'] || '[]');
    
    if (!userId) {
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'UNAUTHORIZED',
          message: 'User authentication required'
        })
      );
    }
    
    // Проверьте, является ли пользователь администратором
    if (!userRoles.includes('admin')) {
      req.log.warn(`Unauthorized admin access attempt by user: ${userId}`);
      return res.status(403).json(
        formatResponse(false, null, {
          code: 'FORBIDDEN',
          message: 'Admin access required'
        })
      );
    }
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    
    // Получить доступ к пользователям с разбивкой по страницам
    const usersResult = await pool.query(
      `SELECT id, email, name, roles, created_at, updated_at 
       FROM users 
       ORDER BY created_at DESC 
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    
    // Получите общее количество
    const countResult = await pool.query('SELECT COUNT(*) FROM users');
    const total = parseInt(countResult.rows[0].count);
    
    req.log.info({ adminId: userId, page, limit }, 'Admin accessed users list');
    
    res.json(
      formatResponse(true, {
        users: usersResult.rows,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      })
    );
  } catch (error) {
    req.log.error('Failed to get users list:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to get users list'
      })
    );
  }
});

// Health check с детальной информацией
app.get('/health', async (req, res) => {
  try {
    // Проверяем соединение с БД
    await pool.query('SELECT 1');
    
    const healthInfo = {
      success: true,
      data: {
        service: 'users-service',
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: 'connected',
        environment: process.env.NODE_ENV || 'development',
        version: '1.0.0'
      }
    };
    
    req.log.debug('Health check passed', healthInfo.data);
    res.json(healthInfo);
  } catch (error) {
    req.log.error('Health check failed:', error);
    res.status(503).json({
      success: false,
      data: {
        service: 'users-service',
        status: 'unhealthy',
        database: 'disconnected',
        timestamp: new Date().toISOString()
      }
    });
  }
});

app.listen(PORT, () => {
  logger.info({
    event: 'service_start',
    port: PORT,
    environment: process.env.NODE_ENV || 'development'
  }, `Users Service running on port ${PORT}`);
});