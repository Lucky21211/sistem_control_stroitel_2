// service_orders/index.js
const express = require('express');
const { Pool } = require('pg');
const pino = require('pino');
const expressPino = require('express-pino-logger');
const { z } = require('zod');

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const expressLogger = expressPino({ logger });

const app = express();
const PORT = process.env.SERVICE_PORT || 3002;

// Database connection
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'taskdb',
  user: process.env.DB_USER || 'admin',
  password: process.env.DB_PASSWORD || 'password',
});

// Validation schemas
const createOrderSchema = z.object({
  items: z.array(z.object({
    product: z.string().min(1, 'Product name is required'),
    quantity: z.number().int().positive('Quantity must be positive'),
    price: z.number().positive('Price must be positive')
  })).min(1, 'At least one item is required'),
  total: z.number().positive('Total must be positive')
});

const updateOrderStatusSchema = z.object({
  status: z.enum(['created', 'in_progress', 'completed', 'cancelled'])
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

// Check if user exists (would call users service in real scenario)
const checkUserExists = async (userId) => {
  const result = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
  return result.rows.length > 0;
};

// Check order ownership
const checkOrderOwnership = async (orderId, userId) => {
  const result = await pool.query(
    'SELECT user_id FROM orders WHERE id = $1',
    [orderId]
  );
  
  if (result.rows.length === 0) return null;
  return result.rows[0].user_id === userId;
};

// Check if user is admin
const isAdmin = (userRoles) => {
  const roles = JSON.parse(userRoles || '[]');
  return roles.includes('admin');
};

// Routes
// Create order
app.post('/v1/orders', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const validatedData = createOrderSchema.parse(req.body);
    
    // Verify user exists
    const userExists = await checkUserExists(userId);
    if (!userExists) {
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'USER_NOT_FOUND',
          message: 'User not found'
        })
      );
    }
    
    // Create order
    const result = await pool.query(
      `INSERT INTO orders (user_id, items, total, status) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, user_id, items, status, total, created_at, updated_at`,
      [userId, JSON.stringify(validatedData.items), validatedData.total, 'created']
    );

    const order = result.rows[0];
    
    req.log.info(`Order created: ${order.id} for user: ${userId}`);
    
    // Domain event: order created (stub for future message broker)
    req.log.info(`DOMAIN_EVENT: ORDER_CREATED - Order: ${order.id}, User: ${userId}`);
    
    res.status(201).json(
      formatResponse(true, { order })
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
        message: 'Failed to create order'
      })
    );
  }
});

// Get order by ID
app.get('/v1/orders/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = req.headers['x-user-roles'];
    const orderId = req.params.id;
    
    const result = await pool.query(
      'SELECT * FROM orders WHERE id = $1',
      [orderId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'ORDER_NOT_FOUND',
          message: 'Order not found'
        })
      );
    }
    
    const order = result.rows[0];
    
    // Check ownership or admin access
    const isOwner = order.user_id === userId;
    const hasAdminAccess = isAdmin(userRoles);
    
    if (!isOwner && !hasAdminAccess) {
      return res.status(403).json(
        formatResponse(false, null, {
          code: 'FORBIDDEN',
          message: 'Access denied to this order'
        })
      );
    }
    
    res.json(
      formatResponse(true, { order })
    );
  } catch (error) {
    req.log.error(error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to get order'
      })
    );
  }
});

// Get user's orders with pagination
app.get('/v1/orders', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = req.headers['x-user-roles'];
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const sortBy = req.query.sortBy || 'created_at';
    const sortOrder = req.query.sortOrder || 'desc';
    
    let query = 'SELECT * FROM orders';
    let countQuery = 'SELECT COUNT(*) FROM orders';
    let queryParams = [];
    
    // If not admin, only show user's orders
    if (!isAdmin(userRoles)) {
      query += ' WHERE user_id = $1';
      countQuery += ' WHERE user_id = $1';
      queryParams = [userId];
    }
    
    // Add sorting and pagination
    query += ` ORDER BY ${sortBy} ${sortOrder} LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    
    const ordersResult = await pool.query(query, queryParams);
    const countResult = await pool.query(countQuery, queryParams.slice(0, 1));
    const total = parseInt(countResult.rows[0].count);
    
    res.json(
      formatResponse(true, {
        orders: ordersResult.rows,
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
        message: 'Failed to get orders list'
      })
    );
  }
});

// Update order status
app.patch('/v1/orders/:id/status', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = req.headers['x-user-roles'];
    const orderId = req.params.id;
    const validatedData = updateOrderStatusSchema.parse(req.body);
    
    // Check order exists and ownership
    const orderOwnership = await checkOrderOwnership(orderId, userId);
    
    if (orderOwnership === null) {
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'ORDER_NOT_FOUND',
          message: 'Order not found'
        })
      );
    }
    
    // Only owner or admin can update status
    if (!orderOwnership && !isAdmin(userRoles)) {
      return res.status(403).json(
        formatResponse(false, null, {
          code: 'FORBIDDEN',
          message: 'Cannot update status of this order'
        })
      );
    }
    
    const result = await pool.query(
      `UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $2 
       RETURNING id, user_id, items, status, total, created_at, updated_at`,
      [validatedData.status, orderId]
    );
    
    const order = result.rows[0];
    
    req.log.info(`Order status updated: ${order.id} to ${validatedData.status}`);
    
    // Domain event: order status updated
    req.log.info(`DOMAIN_EVENT: ORDER_STATUS_UPDATED - Order: ${order.id}, Status: ${validatedData.status}`);
    
    res.json(
      formatResponse(true, { order })
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
        message: 'Failed to update order status'
      })
    );
  }
});

// Cancel order
app.delete('/v1/orders/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const orderId = req.params.id;
    
    // Check order exists and ownership
    const orderOwnership = await checkOrderOwnership(orderId, userId);
    
    if (orderOwnership === null) {
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'ORDER_NOT_FOUND',
          message: 'Order not found'
        })
      );
    }
    
    if (!orderOwnership) {
      return res.status(403).json(
        formatResponse(false, null, {
          code: 'FORBIDDEN',
          message: 'Cannot cancel this order'
        })
      );
    }
    
    const result = await pool.query(
      `UPDATE orders SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP 
       WHERE id = $1 
       RETURNING id, user_id, items, status, total, created_at, updated_at`,
      [orderId]
    );
    
    const order = result.rows[0];
    
    req.log.info(`Order cancelled: ${order.id} by user: ${userId}`);
    
    res.json(
      formatResponse(true, { order })
    );
  } catch (error) {
    req.log.error(error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to cancel order'
      })
    );
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    data: {
      service: 'orders-service',
      status: 'healthy',
      timestamp: new Date().toISOString()
    }
  });
});

app.listen(PORT, () => {
  logger.info(`Orders Service running on port ${PORT}`);
});