// service_orders/middleware/tracing.js
const tracingMiddleware = (req, res, next) => {
  const requestId = req.headers['x-request-id'];
  const userId = req.headers['x-user-id'];
  
  // Создаем child logger с контекстом трассировки
  req.log = req.log.child({ 
    requestId,
    userId,
    trace: {
      service: 'orders-service',
      span: 'request'
    }
  });
  
  // Логируем начало обработки запроса
  req.log.info({
    event: 'request_start',
    method: req.method,
    url: req.url,
    userAgent: req.headers['user-agent']
  }, 'Incoming request');
  
  const start = Date.now();
  
  // Перехватываем завершение response для логирования
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - start;
    
    req.log.info({
      event: 'request_complete',
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`
    }, 'Request completed');
    
    originalSend.call(this, data);
  };
  
  next();
};

module.exports = tracingMiddleware;