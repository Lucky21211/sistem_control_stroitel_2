// service_users/middleware/logger.js
const pino = require('pino');

const createLogger = (serviceName) => {
  return pino({
    name: serviceName,
    level: process.env.LOG_LEVEL || 'info',
    formatters: {
      level: (label) => {
        return { level: label };
      },
      bindings: (bindings) => {
        return { 
          pid: bindings.pid,
          hostname: bindings.hostname,
          service: serviceName
        };
      }
    },
    timestamp: () => `,"time":"${new Date().toISOString()}"`,
    serializers: {
      req: (req) => {
        return {
          method: req.method,
          url: req.url,
          headers: {
            'x-request-id': req.headers['x-request-id'],
            'user-agent': req.headers['user-agent']
          },
          body: req.method !== 'GET' ? req.body : undefined
        };
      },
      res: (res) => {
        return {
          statusCode: res.statusCode
        };
      },
      err: pino.stdSerializers.err
    },
    transport: process.env.NODE_ENV === 'development' ? {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'pid,hostname'
      }
    } : undefined
  });
};

module.exports = { createLogger };