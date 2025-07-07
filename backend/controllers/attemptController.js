const pool = require('../db/client');

// ------------------ Quiz Attempts ------------------

exports.startQuizAttempt = async (req, res) => {
  const { quiz_id } = req.body;
  const user_id = req.user.id;

  try {
    const result = await pool.query(
      `INSERT INTO quiz_attempts (quiz_id, user_id)
       VALUES ($1, $2)
       RETURNING *;`,
      [quiz_id, user_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error starting quiz attempt:', err);
    res.status(500).json({ error: 'Failed to start quiz attempt' });
  }
};

exports.submitQuizAttempt = async (req, res) => {
  const { attempt_id, time_taken, score = 0, is_completed = true } = req.body;

  try {
    const result = await pool.query(
      `UPDATE quiz_attempts
       SET submitted_at = NOW(),
           completed_at = NOW(),
           time_taken = $1,
           score = $2,
           status = $3,
           is_completed = $4,
           updated_at = NOW()
       WHERE id = $5
       RETURNING *;`,
      [
        time_taken || null,
        score,
        is_completed ? 'completed' : 'in_progress',
        is_completed,
        attempt_id
      ]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error submitting quiz attempt:', err);
    res.status(500).json({ error: 'Failed to submit quiz attempt' });
  }
};

exports.getAttemptById = async (req, res) => {
  const attempt_id = req.params.id;

  try {
    const result = await pool.query(
      `SELECT * FROM quiz_attempts WHERE id = $1;`,
      [attempt_id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching quiz attempt:', err);
    res.status(500).json({ error: 'Failed to get attempt' });
  }
};

exports.getAttemptsByUser = async (req, res) => {
  const user_id = req.params.userId;

  try {
    const result = await pool.query(
      `SELECT * FROM quiz_attempts WHERE user_id = $1 ORDER BY started_at DESC;`,
      [user_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching user attempts:', err);
    res.status(500).json({ error: 'Failed to get user attempts' });
  }
};

// ------------------ Question Attempts ------------------

exports.submitQuestionAttempt = async (req, res) => {
  const {
    quiz_attempt_id,
    question_id,
    selected_option_id,
    typed_answer,
    is_correct,
    time_taken
  } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO question_attempts
         (quiz_attempt_id, question_id, selected_option_id, typed_answer, is_correct, time_taken)
       VALUES
         ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (quiz_attempt_id, question_id)
       DO UPDATE SET
         selected_option_id = EXCLUDED.selected_option_id,
         typed_answer = EXCLUDED.typed_answer,
         is_correct = EXCLUDED.is_correct,
         time_taken = EXCLUDED.time_taken,
         attempted_at = CURRENT_TIMESTAMP
       RETURNING *;`,
      [
        quiz_attempt_id,
        question_id,
        selected_option_id || null,
        typed_answer || null,
        is_correct,
        time_taken || null
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error submitting question attempt:', err);
    res.status(500).json({ error: 'Failed to submit question attempt' });
  }
};

exports.updateQuestionAttempt = async (req, res) => {
  const attempt_id = req.params.id;
  const { selected_option_id, typed_answer, is_correct, time_taken } = req.body;

  try {
    const result = await pool.query(
      `UPDATE question_attempts
       SET selected_option_id = $1,
           typed_answer = $2,
           is_correct = $3,
           time_taken = $4,
           attempted_at = NOW()
       WHERE id = $5
       RETURNING *;`,
      [
        selected_option_id || null,
        typed_answer || null,
        is_correct,
        time_taken || null,
        attempt_id
      ]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating question attempt:', err);
    res.status(500).json({ error: 'Failed to update question attempt' });
  }
};

exports.getQuestionAttemptsByQuizAttemptId = async (req, res) => {
  const { quizAttemptId } = req.params;

  try {
    const result = await pool.query(
      `SELECT * FROM question_attempts WHERE quiz_attempt_id = $1 ORDER BY attempted_at;`,
      [quizAttemptId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching question attempts:', err);
    res.status(500).json({ error: 'Failed to get question attempts' });
  }
};

exports.getQuestionAttemptById = async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      `SELECT * FROM question_attempts WHERE id = $1;`,
      [id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching question attempt:', err);
    res.status(500).json({ error: 'Failed to get question attempt' });
  }
};
