const pool = require('../db/client');

exports.getHelp = async (req, res) => {
  res.json({ message: 'Get help content' });
};

exports.submitFeedback = async (req, res) => {
  res.json({ message: 'Submit feedback' });
};

exports.getLanguages = async (req, res) => {
  res.json({ message: 'Get supported languages' });
};

exports.getSchoolSuggestions = async (req, res) => {
  const query = req.query.q?.toLowerCase() || '';

  try {
    const result = await pool.query(`
      SELECT DISTINCT school
      FROM users
      WHERE school IS NOT NULL AND TRIM(school) != ''
    `);

    const matched = result.rows
      .map(row => row.school)
      .filter(school => school.toLowerCase().includes(query));

    res.json({schools: matched});
  } catch (err) {
    console.error('❌ Failed to fetch schools:', err);
    res.status(500).json({ error: 'Failed to fetch schools' });
  }
};