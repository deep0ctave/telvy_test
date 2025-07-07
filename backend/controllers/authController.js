const pool = require('../db/client');
const bcrypt = require('bcrypt');
const { generateAccessToken, generateRefreshToken, verifyAccessToken, verifyRefreshToken } = require('../utils/jwt');
const { sendOtp } = require('../utils/otpUtil');

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


exports.registerInitiate = async (req, res) => {
  try {
    const {
      username, phone, email, password,
      name, gender, dob, school, class: academicClass,
      section, user_type
    } = req.body;

    // Check for existing user (phone/email/username)
    const userCheck = await pool.query(
      `SELECT username, phone, email FROM users WHERE phone = $1 OR email = $2 OR username = $3`,
      [phone, email, username]
    );

    if (userCheck.rows.length > 0) {
      const existing = userCheck.rows[0];

      if (existing.phone === phone) {
        return res.status(409).json({ error: 'Phone number already registered' });
      }
      if (existing.email === email) {
        return res.status(409).json({ error: 'Email already registered' });
      }
      if (existing.username === username) {
        return res.status(409).json({ error: 'Username already taken' });
      }

      return res.status(409).json({ error: 'User already exists' });
    }

    // Expire previous OTPs for this phone
    await pool.query(
      `UPDATE otp_verifications
       SET is_used = TRUE
       WHERE phone = $1 AND is_used = FALSE`,
      [phone]
    );

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = await sendOtp(phone, 'registration');

    const userData = {
      username,
      phone,
      email,
      password: hashedPassword,
      name,
      gender,
      dob,
      school,
      class: academicClass,
      section,
      user_type: user_type || 'student' 
    };

    await pool.query(
      `INSERT INTO otp_verifications (phone, otp, data, expires_at)
       VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
      [phone, otp, userData]
    );

    console.log(`📱 OTP for ${phone}: ${otp}`);

    res.status(200).json({ message: 'OTP sent to phone' });
  } catch (err) {
    console.error('Error in registerInitiate:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.registerVerify = async (req, res) => {
  const { phone, otp } = req.body;

  try {
    const result = await pool.query(
      `SELECT * FROM otp_verifications
       WHERE phone = $1 AND otp = $2 AND is_used = FALSE AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [phone, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const record = result.rows[0];
    const userData = record.data;

    const userInsert = await pool.query(
      `INSERT INTO users (
        username, phone, email, password, name, gender, dob,
        school, class, section, user_type, is_verified
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,TRUE)
      RETURNING id, username, user_type`,
      [
        userData.username,
        userData.phone,
        userData.email,
        userData.password,
        userData.name,
        userData.gender,
        userData.dob,
        userData.school,
        userData.class,
        userData.section,
        userData.user_type
      ]
    ); 

    await pool.query(
      `UPDATE otp_verifications SET is_used = TRUE WHERE id = $1`,
      [record.id]
    );

    res.status(201).json({
      message: 'User verified and registered successfully',
      user: userInsert.rows[0]
    });
  } catch (err) {
    console.error('Error in registerVerify:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


exports.resendOtp = async (req, res) => {
  const { phone } = req.body;

  if (!phone || typeof phone !== 'string') {
    return res.status(400).json({ error: 'Valid phone number required' });
  }

  try {
    const result = await pool.query(
      `SELECT * FROM otp_verifications
       WHERE phone = $1 AND is_used = FALSE AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [phone]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'No pending registration found for this phone number' });
    }

    const oldOtpRecord = result.rows[0];

    // ✅ Mark old OTP as used
    await pool.query(
      `UPDATE otp_verifications SET is_used = TRUE WHERE id = $1`,
      [oldOtpRecord.id]
    );

    // ✅ Generate new OTP
    const newOtp = await sendOtp(phone, 'resend');

    // ✅ Set expiry timestamp
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // ✅ Insert new OTP into DB
    await pool.query(
      `INSERT INTO otp_verifications (phone, otp, data, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [phone, newOtp, oldOtpRecord.data, expiresAt]
    );

    // 🧾 Already logged by sendOtp()
    res.status(200).json({ message: 'OTP resent successfully' });
  } catch (err) {
    console.error('Error in resendOtp:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


exports.forgotPasswordInitiate = async (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  try {
    const result = await pool.query(
      `SELECT id FROM users WHERE phone = $1`,
      [phone]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No user found with this phone number' });
    }

    // Expire old OTPs for password reset
    await pool.query(
      `UPDATE otp_verifications SET is_used = TRUE
       WHERE phone = $1 AND is_used = FALSE AND data->>'context' = 'forgot_password'`,
      [phone]
    );

    const otp = await sendOtp(phone, 'forgot-password');
    const userId = result.rows[0].id;

    const data = {
      user_id: userId,
      context: 'forgot_password'
    };

    await pool.query(
      `INSERT INTO otp_verifications (phone, otp, data, expires_at)
       VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
      [phone, otp, data]
    );

    console.log(`🔐 Forgot password OTP for ${phone}: ${otp}`);
    res.json({ message: 'OTP sent to phone' });
  } catch (err) {
    console.error('Error in forgotPasswordInitiate:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.forgotPasswordResend = async (req, res) => {
  const { phone } = req.body;

  if (!phone || typeof phone !== 'string') {
    return res.status(400).json({ error: 'Valid phone number required' });
  }

  try {
    const result = await pool.query(
      `SELECT * FROM otp_verifications
       WHERE phone = $1 AND is_used = FALSE AND expires_at > NOW()
       AND data->>'context' = 'forgot_password'
       ORDER BY created_at DESC LIMIT 1`,
      [phone]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'No active password reset request found for this phone number' });
    }

    const oldRecord = result.rows[0];

    // Mark old OTP as used
    await pool.query(
      `UPDATE otp_verifications SET is_used = TRUE WHERE id = $1`,
      [oldRecord.id]
    );

    const newOtp = generateOtp();

    await pool.query(
      `INSERT INTO otp_verifications (phone, otp, data, expires_at)
       VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')`,
      [phone, newOtp, oldRecord.data]
    );

    console.log(`🔁 Resent forgot password OTP for ${phone}: ${newOtp}`);

    res.json({ message: 'OTP resent successfully' });
  } catch (err) {
    console.error('Error in forgotPasswordResend:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


exports.forgotPasswordVerify = async (req, res) => {
  const { phone, otp, new_password } = req.body;

  if (!phone || !otp || !new_password) {
    return res.status(400).json({ error: 'Phone, OTP, and new password are required' });
  }

  try {
    const result = await pool.query(
      `SELECT * FROM otp_verifications
       WHERE phone = $1 AND otp = $2 AND is_used = FALSE
       AND expires_at > NOW() AND data->>'context' = 'forgot_password'
       ORDER BY created_at DESC LIMIT 1`,
      [phone, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const record = result.rows[0];
    const userId = record.data.user_id;
    const hashed = await bcrypt.hash(new_password, 10);

    await pool.query(
      `UPDATE users SET password = $1 WHERE id = $2`,
      [hashed, userId]
    );

    await pool.query(
      `UPDATE otp_verifications SET is_used = TRUE WHERE id = $1`,
      [record.id]
    );

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Error in forgotPasswordVerify:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

