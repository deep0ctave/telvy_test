const db = require('../db/client'); // using pg.Pool
const format = require('pg-format');

// Create a quiz
exports.createQuiz = async (req, res) => {
  const { title, description, image_url, time_limit, quiz_type, tags } = req.body;
  const ownerId = req.user.id;

  try {
    const result = await db.query(
      `INSERT INTO quizzes (title, description, image_url, time_limit, quiz_type, tags, owner_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [title, description, image_url, time_limit, quiz_type, tags, ownerId]
    );

    res.status(201).json({ message: 'Quiz created', quiz: result.rows[0] });
  } catch (err) {
    console.error('Create quiz error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Get all quizzes
exports.getAllQuizzes = async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM quizzes ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching quizzes' });
  }
};

// Get single quiz with its questions
exports.getQuizById = async (req, res) => {
  const quizId = req.params.quizId;

  try {
    const quiz = await db.query('SELECT * FROM quizzes WHERE id = $1', [quizId]);
    if (!quiz.rows.length) return res.status(404).json({ message: 'Quiz not found' });

    const questions = await db.query(
      `SELECT q.*, qq.question_order
       FROM quiz_questions qq
       JOIN questions q ON q.id = qq.question_id
       WHERE qq.quiz_id = $1
       ORDER BY qq.question_order ASC`,
      [quizId]
    );

    res.json({ ...quiz.rows[0], questions: questions.rows });
  } catch (err) {
    res.status(500).json({ message: 'Error retrieving quiz' });
  }
};

// Update quiz details
exports.updateQuiz = async (req, res) => {
  const { quizId } = req.params;
  const fields = ['title', 'description', 'image_url', 'time_limit', 'quiz_type', 'tags'];
  const updates = [];
  const values = [];
  let index = 1;

  try {
    // Check if quiz exists
    const quiz = await db.query('SELECT * FROM quizzes WHERE id = $1', [quizId]);
    if (quiz.rowCount === 0) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    // Build update query dynamically
    for (const field of fields) {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = $${index++}`);
        values.push(req.body[field]);
      }
    }

    // If no updates were provided
    if (updates.length === 0) {
      return res.status(400).json({ message: 'No fields provided to update' });
    }

    // Add updated_at and quizId to the update
    updates.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(quizId);

    const query = `
      UPDATE quizzes
      SET ${updates.join(', ')}
      WHERE id = $${values.length}
      RETURNING *
    `;

    const result = await db.query(query, values);

    res.json({ message: 'Quiz updated', quiz: result.rows[0] });
  } catch (err) {
    console.error('Update quiz error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};


// Delete multiple questions from quiz
exports.removeQuestionsFromQuiz = async (req, res, next) => {
  try {
    const quizId = parseInt(req.params.quizId, 10);
    const questionIds = req.body.questionIds;

    if (isNaN(quizId)) {
      return res.status(400).json({ message: 'Invalid quizId' });
    }

    if (!Array.isArray(questionIds) || questionIds.length === 0) {
      return res.status(400).json({ message: 'questionIds must be a non-empty array' });
    }

    const result = await db.query(
      `
      DELETE FROM quiz_questions
      WHERE quiz_id = $1 AND question_id = ANY($2::int[])
      RETURNING *
      `,
      [quizId, questionIds]
    );

    res.json({
      message: `${result.rowCount} question(s) removed from quiz`,
      removed: result.rows,
    });
  } catch (err) {
    console.error('Remove questions from quiz error:', err);
    next(err);
  }
};


exports.deleteQuiz = async (req, res, next) => {
  const { quizId } = req.params;
  const user = req.user;

  try {
    // First, fetch quiz owner (creator)
    const result = await db.query(
      'SELECT created_by FROM quizzes WHERE id = $1',
      [quizId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    const quiz = result.rows[0];

    // Only allow:
    // - Admins (always allowed)
    // - Teachers only if they created the quiz
    if (user.role === 'teacher' && user.id !== quiz.created_by) {
      return res.status(403).json({ message: 'Forbidden: You can only delete your own quizzes' });
    }

    // Delete associated questions from join table
    await db.query(
      'DELETE FROM quiz_questions WHERE quiz_id = $1',
      [quizId]
    );

    // Delete the quiz itself
    await db.query(
      'DELETE FROM quizzes WHERE id = $1',
      [quizId]
    );

    res.json({ message: 'Quiz deleted successfully' });
  } catch (err) {
    next(err);
  }
};

// Add MULTIPLE questions to quiz
exports.addQuestionsToQuiz = async (req, res, next) => {
  try {
    const { quizId } = req.params;
    const { questionIds } = req.body;

    if (!Array.isArray(questionIds) || questionIds.length === 0) {
      return res.status(400).json({ message: 'questionIds must be a non-empty array' });
    }

    // Filter out already existing
    const existing = await db.query(
      `SELECT question_id FROM quiz_questions
       WHERE quiz_id = $1 AND question_id = ANY($2::int[])`,
      [quizId, questionIds]
    );

    const existingIds = existing.rows.map(row => row.question_id);
    const newIds = questionIds.filter(id => !existingIds.includes(id));

    if (newIds.length === 0) {
      return res.status(400).json({ message: 'All questions already exist in the quiz' });
    }

    const values = newIds.map(qid => `(${quizId}, ${qid})`).join(',');
    await db.query(
      `INSERT INTO quiz_questions (quiz_id, question_id)
       VALUES ${values}`
    );

    res.status(201).json({
      message: `${newIds.length} question(s) added to quiz`,
      addedQuestionIds: newIds
    });
  } catch (err) {
    next(err);
  }
};

