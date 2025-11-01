// service_users/index.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const pino = require('pino');
const expressPino = require('express-pino-logger');
const { z } = require('zod');

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
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

// Middleware
app.use(express.json());
app.use(expressLogger);

// Add X-Request-ID to logs
app.use((req, res, next) => {
  req.log = logger.child({ 
    requestId: req.headers['x-request-id'],
    userId: req.headers['x-user-id']
  });
  next();
});

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
    
    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [validatedData.email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(409).json(
        formatResponse(false, null, {
          code: 'USER_EXISTS',
          message: 'User with this email already exists'
        })
      );
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(validatedData.password, saltRounds);

    // Create user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name) 
       VALUES ($1, $2, $3) 
       RETURNING id, email, name, roles, created_at, updated_at`,
      [validatedData.email, passwordHash, validatedData.name]
    );

    const user = result.rows[0];
    
    req.log.info(`User registered: ${user.email}`);
    
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
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error(error);
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
    
    // Find user
    const result = await pool.query(
      'SELECT id, email, password_hash, name, roles FROM users WHERE email = $1',
      [validatedData.email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        })
      );
    }
    
    const user = result.rows[0];
    
    // Check password
    const isValidPassword = await bcrypt.compare(validatedData.password, user.password_hash);
    
    if (!isValidPassword) {
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

    req.log.info(`User logged in: ${user.email}`);
    
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
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error(error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Login failed'
      })
    );
  }
});

// Get current profile
app.get('/v1/profile', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    
    const result = await pool.query(
      'SELECT id, email, name, roles, created_at, updated_at FROM users WHERE id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'USER_NOT_FOUND',
          message: 'User not found'
        })
      );
    }
    
    const user = result.rows[0];
    
    res.json(
      formatResponse(true, { user })
    );
  } catch (error) {
    req.log.error(error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to get profile'
      })
    );
  }
});

// Update profile
app.put('/v1/profile', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const validatedData = updateProfileSchema.parse(req.body);
    
    const result = await pool.query(
      'UPDATE users SET name = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, email, name, roles, created_at, updated_at',
      [validatedData.name, userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'USER_NOT_FOUND',
          message: 'User not found'
        })
      );
    }
    
    const user = result.rows[0];
    
    req.log.info(`Profile updated for user: ${user.email}`);
    
    res.json(
      formatResponse(true, { user })
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error(error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to update profile'
      })
    );
  }
});

// Get users list (admin only)
app.get('/v1/users', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = JSON.parse(req.headers['x-user-roles'] || '[]');
    
    // Check if user is admin
    if (!userRoles.includes('admin')) {
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
    
    // Get users with pagination
    const usersResult = await pool.query(
      `SELECT id, email, name, roles, created_at, updated_at 
       FROM users 
       ORDER BY created_at DESC 
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    
    // Get total count
    const countResult = await pool.query('SELECT COUNT(*) FROM users');
    const total = parseInt(countResult.rows[0].count);
    
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
    req.log.error(error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to get users list'
      })
    );
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    data: {
      service: 'users-service',
      status: 'healthy',
      timestamp: new Date().toISOString()
    }
  });
});

app.listen(PORT, () => {
  logger.info(`Users Service running on port ${PORT}`);
});