const jwt = require('jsonwebtoken');
const pool = require('../../db/client');

const authenticateJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization header missing or malformed' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Optionally check if user still exists
    const result = await pool.query(`SELECT id FROM users WHERE id = $1`, [decoded.id]);
    if (result.rowCount === 0) {
      return res.status(401).json({ message: 'User no longer exists' });
    }

    req.user = decoded;
    req.token = token;

    next();
  } catch (err) {
    console.error('JWT verification failed:', err);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

module.exports = authenticateJWT;
