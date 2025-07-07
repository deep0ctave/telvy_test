const db = require('../db/client');


exports.getAllQuestions = async (req, res, next) => {
  try {
    const result = await db.query('SELECT * FROM questions ORDER BY created_at DESC');
    res.status(200).json({ questions: result.rows });
  } catch (err) {
    next(err);
  }
};

exports.createQuestion = async (req, res, next) => {
  try {
    const {
      question_text,
      question_type,
      tags = [],
      question_image = null,
      options = [],
      accepted_answers = []
    } = req.body;

    const owner_id = req.user.id;

    const questionResult = await db.query(
      `INSERT INTO questions (question_text, question_type, tags, question_image, owner_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [question_text, question_type, tags, question_image, owner_id]
    );

    const question = questionResult.rows[0];
    const questionId = question.id;

    if (question_type === 'mcq') {
      if (!Array.isArray(options) || options.length < 2) {
        return res.status(400).json({ error: 'MCQ must have at least two options' });
      }

      for (const option of options) {
        if (!option.text) {
          return res.status(400).json({ error: 'Option text is required' });
        }

        await db.query(
          `INSERT INTO options (question_id, option_text, is_correct)
           VALUES ($1, $2, $3)`,
          [questionId, option.text, !!option.is_correct]
        );
      }
    }

    if (question_type === 'type_in') {
      if (!Array.isArray(accepted_answers) || accepted_answers.length === 0) {
        return res.status(400).json({ error: 'Type-in questions must have at least one accepted answer' });
      }

      for (const answer of accepted_answers) {
        await db.query(
          `INSERT INTO accepted_answers (question_id, acceptable_answer)
           VALUES ($1, $2)`,
          [questionId, answer]
        );
      }
    }

    res.status(201).json({ message: 'Question created', question });
  } catch (err) {
    next(err);
  }
};

exports.getQuestionById = async (req, res, next) => {
  try {
    const { id } = req.params;

    const questionResult = await db.query('SELECT * FROM questions WHERE id = $1', [id]);
    if (questionResult.rowCount === 0) return res.status(404).json({ message: 'Question not found' });

    const question = questionResult.rows[0];
    const options = await db.query('SELECT id, option_text, is_correct FROM options WHERE question_id = $1', [id]);
    const acceptedAnswers = await db.query('SELECT acceptable_answer FROM accepted_answers WHERE question_id = $1', [id]);

    question.options = options.rows;
    question.accepted_answers = acceptedAnswers.rows.map(a => a.acceptable_answer);

    res.status(200).json({ question });
  } catch (err) {
    next(err);
  }
};

exports.updateQuestion = async (req, res, next) => {
  try {
    const { id } = req.params;
    const {
      question_text,
      question_type,
      tags = [],
      question_image = null,
      options = [],
      accepted_answers = []
    } = req.body;

    const userId = req.user.id;
    const role = req.user.role;

    const existing = await db.query('SELECT * FROM questions WHERE id = $1', [id]);
    if (existing.rowCount === 0)
      return res.status(404).json({ message: 'Question not found' });

    const question = existing.rows[0];
    if (role === 'teacher' && question.owner_id !== userId) {
      return res.status(403).json({ message: 'Unauthorized: Not your question' });
    }

    await db.query(
      `UPDATE questions SET
         question_text = $1,
         question_type = $2,
         tags = $3,
         question_image = $4,
         updated_at = CURRENT_TIMESTAMP
       WHERE id = $5`,
      [question_text, question_type, tags, question_image, id]
    );

    await db.query('DELETE FROM options WHERE question_id = $1', [id]);
    await db.query('DELETE FROM accepted_answers WHERE question_id = $1', [id]);

    if (question_type === 'mcq') {
      for (const option of options) {
        if (!option.text) {
          return res.status(400).json({ error: 'Option text is required' });
        }
        await db.query(
          `INSERT INTO options (question_id, option_text, is_correct)
           VALUES ($1, $2, $3)`,
          [id, option.text, !!option.is_correct]
        );
      }
    }

    if (question_type === 'type_in') {
      for (const answer of accepted_answers) {
        await db.query(
          `INSERT INTO accepted_answers (question_id, acceptable_answer)
           VALUES ($1, $2)`,
          [id, answer]
        );
      }
    }

    res.status(200).json({ message: 'Question updated' });
  } catch (err) {
    next(err);
  }
};

exports.deleteQuestion = async (req, res, next) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;
    const role = req.user.role;

    const existing = await db.query('SELECT * FROM questions WHERE id = $1', [id]);
    if (existing.rowCount === 0)
      return res.status(404).json({ message: 'Question not found' });

    const question = existing.rows[0];
    if (role === 'teacher' && question.owner_id !== userId) {
      return res.status(403).json({ message: 'Unauthorized: Not your question' });
    }

    await db.query('DELETE FROM questions WHERE id = $1', [id]);
    res.status(200).json({ message: 'Question deleted' });
  } catch (err) {
    next(err);
  }
};