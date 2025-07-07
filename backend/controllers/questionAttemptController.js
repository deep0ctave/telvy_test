const db = require('../db/client');

// Record a question attempt
exports.recordAttempt = async (req, res, next) => {
  const { quiz_attempt_id, question_id, selected_option_id, typed_answer, time_taken } = req.body;
  const userId = req.user?.id;

  if (!quiz_attempt_id || !question_id) {
    return res.status(400).json({ message: 'Missing quiz_attempt_id or question_id' });
  }

  try {
    // Check if this attempt already exists
    const existing = await db.query(
      `SELECT * FROM question_attempts WHERE quiz_attempt_id = $1 AND question_id = $2`,
      [quiz_attempt_id, question_id]
    );

    if (existing.rows.length > 0) {
      // Update existing attempt
      const updated = await db.query(
        `UPDATE question_attempts
         SET selected_option_id = $1,
             typed_answer = $2,
             time_taken = $3,
             attempted_at = CURRENT_TIMESTAMP
         WHERE quiz_attempt_id = $4 AND question_id = $5
         RETURNING *`,
        [selected_option_id, typed_answer, time_taken, quiz_attempt_id, question_id]
      );
      return res.json({ message: 'Question attempt updated', attempt: updated.rows[0] });
    }

    // Insert new attempt
    const result = await db.query(
      `INSERT INTO question_attempts
       (quiz_attempt_id, question_id, selected_option_id, typed_answer, time_taken)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [quiz_attempt_id, question_id, selected_option_id, typed_answer, time_taken]
    );

    res.status(201).json({ message: 'Question attempt recorded', attempt: result.rows[0] });

  } catch (err) {
    next(err);
  }
};

// Get all question attempts for a quiz attempt
exports.getAttemptsByQuizAttempt = async (req, res, next) => {
  const { quizAttemptId } = req.params;
  const userId = req.user?.id;
  const userRole = req.user?.role;

  try {
    // Confirm that the quiz attempt belongs to the user (unless admin/teacher)
    const quizAttemptResult = await db.query(
      `SELECT * FROM quiz_attempts WHERE id = $1`,
      [quizAttemptId]
    );

    if (quizAttemptResult.rows.length === 0) {
      return res.status(404).json({ message: 'Quiz attempt not found' });
    }

    const quizAttempt = quizAttemptResult.rows[0];

    // Only allow access if the user owns it or is admin/teacher
    if (quizAttempt.user_id !== userId && !['admin', 'teacher'].includes(userRole)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Fetch all question attempts for the quiz_attempt_id
    const attempts = await db.query(
      `SELECT * FROM question_attempts WHERE quiz_attempt_id = $1 ORDER BY attempted_at ASC`,
      [quizAttemptId]
    );

    res.json({ attempts: attempts.rows });

  } catch (err) {
    next(err);
  }
};

