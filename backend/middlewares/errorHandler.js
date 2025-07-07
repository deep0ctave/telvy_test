// /middlewares/errorHandler.js

module.exports = (err, req, res, next) => {
  console.error('Global Error:', err.stack || err);

  const statusCode = err.statusCode || 500;

  res.status(statusCode).json({
    success: false,
    error: {
      message: err.message || 'Internal Server Error',
      ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
    }
  });
};
