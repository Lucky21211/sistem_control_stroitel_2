const express = require('express');
const { Pool } = require('pg');
const { createLogger } = require('./middleware/logger');
const tracingMiddleware = require('./middleware/tracing');
const expressPino = require('express-pino-logger');
const { z } = require('zod');

const logger = createLogger('orders-service');
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

// CORS middleware


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

// Проверьте право собственности на заказ
const checkOrderOwnership = async (orderId, userId) => {
  const result = await pool.query(
    'SELECT user_id FROM orders WHERE id = $1',
    [orderId]
  );
  
  if (result.rows.length === 0) return null;
  return result.rows[0].user_id === userId;
};

// Проверьте, является ли пользователь администратором
const isAdmin = (userRoles) => {
  const roles = JSON.parse(userRoles || '[]');
  return roles.includes('admin');
};

// Domain events (по ТЗ)
const publishDomainEvent = (req, eventType, payload) => {
  req.log.info({
    event: 'DOMAIN_EVENT',
    type: eventType,
    payload,
    service: 'orders-service'
  }, `Domain event: ${eventType}`);
  

};

// Routes

// Create order
app.post('/v1/orders', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = req.headers['x-user-roles'];
    
    if (!userId) {
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'UNAUTHORIZED',
          message: 'User authentication required'
        })
      );
    }

    // Полноценная валидация с Zod
    const validatedData = createOrderSchema.parse(req.body);
    
    // Проверка существования пользователя (по ТЗ)
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE id = $1',
      [userId]
    );
    
    if (userCheck.rows.length === 0) {
      req.log.warn(`Order creation failed: user not found - ${userId}`);
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'USER_NOT_FOUND',
          message: 'User not found'
        })
      );
    }

    // Создаем заказ
    const result = await pool.query(
      `INSERT INTO orders (user_id, items, total, status) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, user_id, items, status, total, created_at, updated_at`,
      [userId, JSON.stringify(validatedData.items), validatedData.total, 'created']
    );

    const order = result.rows[0];
    
    req.log.info({ 
      orderId: order.id, 
      userId: order.user_id,
      total: order.total,
      itemsCount: validatedData.items.length 
    }, 'Order created successfully');
    
    // Доменное событие: создан заказ (по ТЗ)
    publishDomainEvent(req, 'ORDER_CREATED', {
      orderId: order.id,
      userId: order.user_id,
      total: order.total,
      items: validatedData.items,
      status: 'created',
      timestamp: new Date().toISOString()
    });
    
    res.status(201).json(
      formatResponse(true, { order })
    );
    
  } catch (error) {
    if (error instanceof z.ZodError) {
      req.log.warn('Order creation validation failed', { errors: error.errors });
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error('Order creation failed:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to create order'
      })
    );
  }
});

// Получить заказ по ID
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
      req.log.warn(`Order not found: ${orderId}`);
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'ORDER_NOT_FOUND',
          message: 'Order not found'
        })
      );
    }
    
    const order = result.rows[0];
    
    // Проверьте права собственности или администратора
    const isOwner = order.user_id === userId;
    const hasAdminAccess = isAdmin(userRoles);
    
    if (!isOwner && !hasAdminAccess) {
      req.log.warn(`Unauthorized access to order: ${orderId} by user: ${userId}`);
      return res.status(403).json(
        formatResponse(false, null, {
          code: 'FORBIDDEN',
          message: 'Access denied to this order'
        })
      );
    }
    
    req.log.debug({ orderId }, 'Order retrieved successfully');
    res.json(
      formatResponse(true, { order })
    );
  } catch (error) {
    req.log.error('Failed to get order:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to get order'
      })
    );
  }
});

// Получайте заказы пользователей с разбивкой по страницам
app.get('/v1/orders', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = req.headers['x-user-roles'];
    
    if (!userId) {
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'UNAUTHORIZED',
          message: 'User authentication required'
        })
      );
    }
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const sortBy = req.query.sortBy || 'created_at';
    const sortOrder = req.query.sortOrder || 'desc';
    
    let query = 'SELECT * FROM orders';
    let countQuery = 'SELECT COUNT(*) FROM orders';
    let queryParams = [];
    
    // Если вы не являетесь администратором, показывайте только заказы пользователя
    if (!isAdmin(userRoles)) {
      query += ' WHERE user_id = $1';
      countQuery += ' WHERE user_id = $1';
      queryParams = [userId];
    }
    
    // Добавьте сортировку и разбивку по страницам
    query += ` ORDER BY ${sortBy} ${sortOrder} LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    
    const ordersResult = await pool.query(query, queryParams);
    const countResult = await pool.query(countQuery, queryParams.slice(0, 1));
    const total = parseInt(countResult.rows[0].count);
    
    req.log.info({ 
      userId, 
      page, 
      limit, 
      totalOrders: total,
      isAdmin: isAdmin(userRoles)
    }, 'Orders list retrieved');
    
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
    req.log.error('Failed to get orders list:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to get orders list'
      })
    );
  }
});

// Обновить статус заказа
app.patch('/v1/orders/:id/status', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const userRoles = req.headers['x-user-roles'];
    const orderId = req.params.id;
    
    if (!userId) {
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'UNAUTHORIZED',
          message: 'User authentication required'
        })
      );
    }
    
    const validatedData = updateOrderStatusSchema.parse(req.body);
    
    // Проверьте наличие заказа и права собственности
    const orderOwnership = await checkOrderOwnership(orderId, userId);
    
    if (orderOwnership === null) {
      req.log.warn(`Order not found for status update: ${orderId}`);
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'ORDER_NOT_FOUND',
          message: 'Order not found'
        })
      );
    }
    
    // Только владелец или администратор может обновлять статус
    if (!orderOwnership && !isAdmin(userRoles)) {
      req.log.warn(`Unauthorized status update attempt: order ${orderId} by user ${userId}`);
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
    
    req.log.info({ 
      orderId: order.id, 
      oldStatus: order.status, 
      newStatus: validatedData.status,
      updatedBy: userId 
    }, 'Order status updated');
    
    // Domain event: 
    publishDomainEvent(req, 'ORDER_STATUS_UPDATED', {
      orderId: order.id,
      userId: order.user_id,
      oldStatus: order.status,
      newStatus: validatedData.status,
      updatedBy: userId,
      timestamp: new Date().toISOString()
    });
    
    res.json(
      formatResponse(true, { order })
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      req.log.warn('Status update validation failed', { errors: error.errors });
      return res.status(400).json(
        formatResponse(false, null, {
          code: 'VALIDATION_ERROR',
          message: error.errors[0].message
        })
      );
    }
    
    req.log.error('Failed to update order status:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to update order status'
      })
    );
  }
});


app.delete('/v1/orders/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const orderId = req.params.id;
    
    if (!userId) {
      return res.status(401).json(
        formatResponse(false, null, {
          code: 'UNAUTHORIZED',
          message: 'User authentication required'
        })
      );
    }
    
    
    const orderOwnership = await checkOrderOwnership(orderId, userId);
    
    if (orderOwnership === null) {
      req.log.warn(`Order not found for cancellation: ${orderId}`);
      return res.status(404).json(
        formatResponse(false, null, {
          code: 'ORDER_NOT_FOUND',
          message: 'Order not found'
        })
      );
    }
    
    if (!orderOwnership) {
      req.log.warn(`Unauthorized cancellation attempt: order ${orderId} by user ${userId}`);
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
    
    req.log.info({ 
      orderId: order.id, 
      userId: userId 
    }, 'Order cancelled');
    
    
    publishDomainEvent(req, 'ORDER_CANCELLED', {
      orderId: order.id,
      userId: order.user_id,
      cancelledBy: userId,
      timestamp: new Date().toISOString()
    });
    
    res.json(
      formatResponse(true, { order })
    );
  } catch (error) {
    req.log.error('Failed to cancel order:', error);
    res.status(500).json(
      formatResponse(false, null, {
        code: 'INTERNAL_ERROR',
        message: 'Failed to cancel order'
      })
    );
  }
});

// Health check с проверкой БД
app.get('/health', async (req, res) => {
  try {
    // Проверяем соединение с БД
    await pool.query('SELECT 1');
    
    const healthInfo = {
      success: true,
      data: {
        service: 'orders-service',
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
        service: 'orders-service',
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
  }, `Orders Service running on port ${PORT}`);
});