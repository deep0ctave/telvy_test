const pool = require('../db/client');
const bcrypt = require('bcrypt');
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require('../utils/jwt');

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
};

exports.login = async (req, res) => {
  const { username, password, force = false } = req.body;

  try {
    const result = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

    const existingSessions = await pool.query(
      `SELECT * FROM user_sessions WHERE user_id = $1 AND is_active = TRUE`,
      [user.id]
    );

    if (existingSessions.rowCount > 0 && !force) {
      return res.status(409).json({
        message: 'User already logged in elsewhere. Use force=true to override.',
      });
    }

    if (force && existingSessions.rowCount > 0) {
      await pool.query(
        `UPDATE user_sessions SET is_active = FALSE WHERE user_id = $1`,
        [user.id]
      );
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    const expiresAt = new Date(Date.now() + COOKIE_OPTIONS.maxAge);

    await pool.query(
      `INSERT INTO user_sessions (user_id, refresh_token, is_active, expires_at)
       VALUES ($1, $2, TRUE, $3)`,
      [user.id, refreshToken, expiresAt]
    );

    res
      .cookie('refreshToken', refreshToken, COOKIE_OPTIONS)
      .json({
        message: 'Login successful',
        accessToken,
        user: {
          id: user.id,
          username: user.username,
          role: user.user_type,
          name: user.name,
        },
      });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Something went wrong during login' });
  }
};

exports.logout = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  const userId = req.user?.id;

  if (!refreshToken || !userId) {
    return res.status(400).json({ error: 'Missing refresh token or user info' });
  }

  try {
    const result = await pool.query(
      `DELETE FROM user_sessions WHERE user_id = $1 AND refresh_token = $2`,
      [userId, refreshToken]
    );

    res.clearCookie('refreshToken', COOKIE_OPTIONS);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Session not found or already logged out' });
    }

    res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Server error during logout' });
  }
};

exports.refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token not found in cookies' });
  }

  try {
    const decoded = verifyRefreshToken(refreshToken);

    const result = await pool.query(
      `SELECT * FROM user_sessions
       WHERE user_id = $1 AND refresh_token = $2 AND is_active = TRUE`,
      [decoded.id, refreshToken]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ error: 'Session not found or token invalid' });
    }

    const newAccessToken = generateAccessToken(decoded);
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error('Refresh token error:', err);
    return res.status(401).json({ error: 'Invalid refresh token' });
  }
};
