const db = require('../db/client');
const bcrypt = require('bcrypt');
const { sendOtp } = require('../utils/otpUtil');

// ✅ Get current user's profile
exports.getProfile = async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await db.query(
      `SELECT id, username, phone, email, name, gender, dob, school, class, section, user_type, is_verified, created_at, updated_at 
       FROM users WHERE id = $1`,
      [userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('getProfile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// ✅ Admin: get all users
exports.getAllUsers = async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, username, phone, email, name, gender, dob, user_type, is_verified, school, class, section FROM users ORDER BY created_at DESC`
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error('getAllUsers error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


// ✅ Admin: get specific user by ID
exports.getUserById = async (req, res) => {
  const userId = req.params.id;

  try {
    const result = await db.query(
      `SELECT id, username, phone, email, name, gender, dob, school, class, section, user_type, is_verified, created_at, updated_at 
       FROM users WHERE id = $1`,
      [userId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('getUserById error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// ✅ Update own profile (or admin updating any)
exports.updateProfile = async (req, res) => {
  const userId = req.user.id;
  const { current_password, old_password, new_password, phone, ...fieldsToUpdate } = req.body;

  try {
    const result = await db.query(`SELECT * FROM users WHERE id = $1`, [userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const disallowed = ['username', 'user_type', 'id', 'created_at', 'updated_at', 'is_verified'];
    for (const key of disallowed) {
      if (req.body.hasOwnProperty(key)) {
        return res.status(400).json({ error: `${key} cannot be updated` });
      }
    }

    const validPassword = await bcrypt.compare(current_password || '', user.password);
    if (!validPassword) return res.status(403).json({ error: 'Current password is incorrect' });

    // Password change flow
    if (new_password && old_password) {
      const oldMatch = await bcrypt.compare(old_password, user.password);
      if (!oldMatch) return res.status(403).json({ error: 'Old password is incorrect' });

      const hashed = await bcrypt.hash(new_password, 10);
      const otp = await sendOtp(user.phone, 'password_change');
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

      await db.query(
        `INSERT INTO otp_verifications (phone, otp, data, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [user.phone, otp, { context: 'password_change', user_id: user.id, new_password: hashed }, expiresAt]
      );

      return res.status(202).json({ message: 'OTP sent to phone. Verify to complete password change.' });
    }

    // Phone number change flow
    if (phone && phone !== user.phone) {
      const phoneTaken = await db.query(`SELECT id FROM users WHERE phone = $1`, [phone]);
      if (phoneTaken.rowCount > 0) return res.status(409).json({ error: 'Phone number already in use' });

      const otp = await sendOtp(phone, 'phone_change');
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

      await db.query(
        `INSERT INTO otp_verifications (phone, otp, data, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [phone, otp, { context: 'phone_change', user_id: user.id }, expiresAt]
      );

      return res.status(202).json({ message: 'OTP sent to new phone. Verify to update.' });
    }

    // Normal profile update
    const keys = Object.keys(fieldsToUpdate);
    if (!keys.length) return res.status(400).json({ error: 'No valid fields to update' });

    const updateSQL = keys.map((f, i) => `${f} = $${i + 1}`).join(', ');
    const updateValues = keys.map(k => fieldsToUpdate[k]);

    await db.query(
      `UPDATE users SET ${updateSQL}, updated_at = NOW() WHERE id = $${keys.length + 1}`,
      [...updateValues, userId]
    );

    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('updateProfile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};
// ✅ Admin: update any user by ID
exports.updateUserById = async (req, res) => {
  const userId = req.params.id;
  const {
    name,
    phone,
    email,
    user_type,
    is_verified,
    dob,
    gender,
    school,
    class: className,
    section,
    username // disallowed
  } = req.body;

  try {
    // Check if user exists
    const result = await db.query(`SELECT * FROM users WHERE id = $1`, [userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });

    // ❌ Disallow username update
    if (username && username !== user.username) {
      return res.status(400).json({ error: 'Username cannot be updated' });
    }

    // ✅ Build dynamic update fields
    const updates = [];
    const values = [];
    let idx = 1;

    const fields = {
      name,
      phone,
      email,
      user_type,
      is_verified,
      dob,
      gender,
      school,
      class: className,
      section
    };

    for (const key in fields) {
      if (fields[key] !== undefined) {
        updates.push(`${key} = $${idx++}`);
        values.push(fields[key]);
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    values.push(userId); // last value = user ID
    const query = `UPDATE users SET ${updates.join(', ')}, updated_at = NOW() WHERE id = $${idx}`;

    await db.query(query, values);

    res.json({ message: 'User updated successfully by admin' });
  } catch (err) {
    console.error('Admin updateUserById error:', err);

    // ✅ Handle unique constraint violations
    if (err.code === '23505') {
      if (err.constraint === 'users_phone_key') {
        return res.status(400).json({ error: 'Phone number already in use' });
      }
      if (err.constraint === 'users_username_key') {
        return res.status(400).json({ error: 'Username already in use' });
      }
    }

    return res.status(500).json({ error: 'Server error' });
  }
};



// ✅ Admin: delete user
exports.deleteUser = async (req, res) => {
  const userId = req.params.id;

  try {
    const result = await db.query('DELETE FROM users WHERE id = $1 RETURNING *', [userId]);
    if (!result.rowCount) return res.status(404).json({ error: 'User not found or already deleted' });

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('deleteUser error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// ✅ Verify OTP for phone change
exports.verifyPhoneChange = async (req, res) => {
  const userId = req.user.id;
  const { phone, otp } = req.body;

  if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP are required' });

  try {
    const otpResult = await db.query(
      `SELECT * FROM otp_verifications
       WHERE phone = $1 AND otp = $2 AND is_used = FALSE AND expires_at > NOW()
       AND data->>'context' = 'phone_change'
       ORDER BY created_at DESC LIMIT 1`,
      [phone, otp]
    );

    if (!otpResult.rowCount) return res.status(400).json({ error: 'Invalid or expired OTP' });

    await db.query(`UPDATE users SET phone = $1, updated_at = NOW() WHERE id = $2`, [phone, userId]);
    await db.query(`UPDATE otp_verifications SET is_used = TRUE WHERE id = $1`, [otpResult.rows[0].id]);

    res.json({ message: 'Phone number updated successfully' });
  } catch (err) {
    console.error('verifyPhoneChange error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// ✅ Verify OTP for password change
exports.verifyPasswordChange = async (req, res) => {
  const userId = req.user.id;
  const { otp, new_password } = req.body;

  if (!otp || !new_password) return res.status(400).json({ error: 'OTP and new password are required' });

  try {
    const otpResult = await db.query(
      `SELECT * FROM otp_verifications
       WHERE phone = (SELECT phone FROM users WHERE id = $1)
       AND otp = $2 AND is_used = FALSE AND expires_at > NOW()
       AND data->>'context' = 'password_change'
       ORDER BY created_at DESC LIMIT 1`,
      [userId, otp]
    );

    if (!otpResult.rowCount) return res.status(400).json({ error: 'Invalid or expired OTP' });

    const hashed = await bcrypt.hash(new_password, 10);
    await db.query(`UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2`, [hashed, userId]);
    await db.query(`UPDATE otp_verifications SET is_used = TRUE WHERE id = $1`, [otpResult.rows[0].id]);

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('verifyPasswordChange error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.createUser = async (req, res) => {
  try {
    const {
      username,
      name,
      phone,
      email,
      dob,
      user_type,
      school,
      class: classInfo,
      section,
      password,
    } = req.body;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      `INSERT INTO users (username, name, phone, email, dob, user_type, school, class, section, password)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, username, name, phone, email, user_type, school, class, section, dob`,
      [username, name, phone, email, dob, user_type, school, classInfo, section, hashedPassword]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    console.error("createUser error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
