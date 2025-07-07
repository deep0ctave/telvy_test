// controllers/quizFullController.js
const db = require('../db/client');


exports.getAllFullQuizzes = async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, title, description, quiz_type, time_limit, tags, image_url, created_at
       FROM quizzes
       ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('getAllFullQuizzes error:', err);
    res.status(500).json({ message: 'Failed to fetch quizzes' });
  }
};


exports.createFullQuiz = async (req, res) => {
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const {
      title,
      description,
      image_url,
      time_limit,
      quiz_type,
      tags,
      questions
    } = req.body;
    const owner_id = req.user.id;

    const quizResult = await client.query(
      `INSERT INTO quizzes (title, description, image_url, time_limit, quiz_type, tags, owner_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [title, description, image_url, time_limit, quiz_type, tags, owner_id]
    );
    const quiz = quizResult.rows[0];

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      const questionRes = await client.query(
        `INSERT INTO questions (question_text, question_image, question_type, tags, owner_id)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [q.question_text, q.question_image || null, q.question_type, q.tags || [], owner_id]
      );

      const question = questionRes.rows[0];

      await client.query(
        `INSERT INTO quiz_questions (quiz_id, question_id, question_order)
         VALUES ($1, $2, $3)`,
        [quiz.id, question.id, i]
      );

      if (q.question_type === 'mcq' || q.question_type === 'true_false') {
        for (const opt of q.options) {
          await client.query(
            `INSERT INTO options (question_id, option_text, is_correct)
             VALUES ($1, $2, $3)`,
            [question.id, opt.text, opt.is_correct]
          );
        }
      } else if (q.question_type === 'type_in') {
        for (const ans of q.accepted_answers || []) {
          await client.query(
            `INSERT INTO accepted_answers (question_id, acceptable_answer)
             VALUES ($1, $2)`,
            [question.id, ans]
          );
        }
      }
    }

    await client.query('COMMIT');
    res.status(201).json({ message: 'Quiz with questions created', quiz_id: quiz.id });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('createFullQuiz error:', err);
    res.status(500).json({ message: 'Failed to create quiz structure' });
  } finally {
    client.release();
  }
};

exports.getFullQuiz = async (req, res) => {
  const quizId = req.params.quizId;
  try {
    const quizRes = await db.query('SELECT * FROM quizzes WHERE id = $1', [quizId]);
    if (!quizRes.rowCount) return res.status(404).json({ message: 'Quiz not found' });

    const questionsRes = await db.query(
      `SELECT q.*, qq.question_order
       FROM quiz_questions qq
       JOIN questions q ON qq.question_id = q.id
       WHERE qq.quiz_id = $1
       ORDER BY qq.question_order`,
      [quizId]
    );

    const fullQuestions = await Promise.all(
      questionsRes.rows.map(async (q) => {
        if (q.question_type === 'mcq' || q.question_type === 'true_false') {
          const options = await db.query(
            `SELECT id, option_text, is_correct FROM options WHERE question_id = $1`,
            [q.id]
          );
          return { ...q, options: options.rows };
        } else if (q.question_type === 'type_in') {
          const answers = await db.query(
            `SELECT acceptable_answer FROM accepted_answers WHERE question_id = $1`,
            [q.id]
          );
          return { ...q, accepted_answers: answers.rows.map(a => a.acceptable_answer) };
        } else {
          return q;
        }
      })
    );

    res.json({ ...quizRes.rows[0], questions: fullQuestions });
  } catch (err) {
    console.error('getFullQuiz error:', err);
    res.status(500).json({ message: 'Failed to fetch full quiz' });
  }
};

exports.updateFullQuiz = async (req, res) => {
  const { quizId } = req.params;
  const client = await db.connect();

  try {
    await client.query('BEGIN');

    const quizRes = await client.query('SELECT * FROM quizzes WHERE id = $1', [quizId]);
    if (!quizRes.rowCount) {
      return res.status(404).json({ message: 'Quiz not found' });
    }

    const {
      title,
      description,
      image_url,
      time_limit,
      quiz_type,
      tags,
      questions
    } = req.body;

    // Validate quiz metadata
    if (!title?.trim()) return res.status(400).json({ message: 'Quiz title is required' });
    if (!description?.trim()) return res.status(400).json({ message: 'Quiz description is required' });
    if (!quiz_type) return res.status(400).json({ message: 'Quiz type is required' });
    if (!Array.isArray(tags)) return res.status(400).json({ message: 'Tags must be an array' });
    if (!Array.isArray(questions) || questions.length === 0) {
      return res.status(400).json({ message: 'At least one question is required' });
    }

    console.log(`[UPDATE QUIZ] quizId: ${quizId}, title: ${title}`);

    // Update quiz metadata
    await client.query(
      `UPDATE quizzes
       SET title = $1, description = $2, image_url = $3, time_limit = $4,
           quiz_type = $5, tags = $6, updated_at = CURRENT_TIMESTAMP
       WHERE id = $7`,
      [title, description, image_url, time_limit, quiz_type, tags, quizId]
    );

    // Clear existing question mappings
    await client.query('DELETE FROM quiz_questions WHERE quiz_id = $1', [quizId]);

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      const index = i + 1;

      if (!q.question_text?.trim()) {
        return res.status(400).json({ message: `Question ${index} is missing text` });
      }

      if (!q.question_type || !['mcq', 'true_false', 'type_in'].includes(q.question_type)) {
        return res.status(400).json({ message: `Question ${index} has invalid or missing type` });
      }

      let questionId = q.id;
      let isNew = false;

      // Insert or update question
      if (!questionId) {
        const result = await client.query(
          `INSERT INTO questions (question_text, question_image, question_type, tags, owner_id)
           VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [q.question_text, q.question_image || null, q.question_type, q.tags || [], req.user.id]
        );
        questionId = result.rows[0].id;
        isNew = true;
      } else {
        const exists = await client.query('SELECT id FROM questions WHERE id = $1', [questionId]);

        if (!exists.rowCount) {
          const result = await client.query(
            `INSERT INTO questions (question_text, question_image, question_type, tags, owner_id)
             VALUES ($1, $2, $3, $4, $5) RETURNING id`,
            [q.question_text, q.question_image || null, q.question_type, q.tags || [], req.user.id]
          );
          questionId = result.rows[0].id;
          isNew = true;
        } else {
          await client.query(
            `UPDATE questions
             SET question_text = $1, question_image = $2, question_type = $3, tags = $4,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $5`,
            [q.question_text, q.question_image || null, q.question_type, q.tags || [], questionId]
          );

          // Clear old options/answers
          await client.query('DELETE FROM options WHERE question_id = $1', [questionId]);
          await client.query('DELETE FROM accepted_answers WHERE question_id = $1', [questionId]);
        }
      }

      // Link to quiz
      await client.query(
        `INSERT INTO quiz_questions (quiz_id, question_id, question_order)
         VALUES ($1, $2, $3)`,
        [quizId, questionId, i]
      );

      // Handle options or answers
      if (['mcq', 'true_false'].includes(q.question_type)) {
        if (!Array.isArray(q.options) || q.options.length === 0) {
          return res.status(400).json({ message: `Question ${index} must have options` });
        }

        let hasCorrect = false;

        for (const [j, opt] of q.options.entries()) {
          const text = (opt.option_text || "").trim();
          if (!text) {
            return res.status(400).json({ message: `Option ${j + 1} of question ${index} is empty` });
          }

          if (opt.is_correct) hasCorrect = true;

          await client.query(
            `INSERT INTO options (question_id, option_text, is_correct)
             VALUES ($1, $2, $3)`,
            [questionId, text, !!opt.is_correct]
          );
        }

        if (!hasCorrect) {
          return res.status(400).json({ message: `Question ${index} must have at least one correct option` });
        }
      }

      if (q.question_type === 'type_in') {
        if (!Array.isArray(q.accepted_answers) || q.accepted_answers.length === 0) {
          return res.status(400).json({ message: `Question ${index} must have accepted answers` });
        }

        let hasAnswer = false;

        for (const [j, ans] of q.accepted_answers.entries()) {
          const answer = (ans || "").trim();
          if (!answer) {
            return res.status(400).json({ message: `Answer ${j + 1} of question ${index} is empty` });
          }

          hasAnswer = true;

          await client.query(
            `INSERT INTO accepted_answers (question_id, acceptable_answer)
             VALUES ($1, $2)`,
            [questionId, answer]
          );
        }

        if (!hasAnswer) {
          return res.status(400).json({ message: `Question ${index} must have at least one valid answer` });
        }
      }
    }

    await client.query('COMMIT');
    console.log(`[UPDATE QUIZ] Quiz ${quizId} updated successfully`);
    res.json({ message: 'Full quiz updated successfully' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[UPDATE QUIZ ERROR]', err);
    res.status(500).json({ message: 'Failed to update quiz structure' });
  } finally {
    client.release();
  }
};



exports.deleteFullQuiz = async (req, res) => {
  const { quizId } = req.params;
  const { deleteQuestions } = req.query; // ?deleteQuestions=true
  const client = await db.connect();

  try {
    await client.query('BEGIN');

    const quizRes = await client.query('SELECT * FROM quizzes WHERE id = $1', [quizId]);
    if (!quizRes.rowCount) return res.status(404).json({ message: 'Quiz not found' });

    const questionIdsRes = await client.query(
      'SELECT question_id FROM quiz_questions WHERE quiz_id = $1',
      [quizId]
    );
    const questionIds = questionIdsRes.rows.map(row => row.question_id);

    // Unlink questions
    await client.query('DELETE FROM quiz_questions WHERE quiz_id = $1', [quizId]);

    if (deleteQuestions === 'true') {
      for (const qid of questionIds) {
        await client.query('DELETE FROM options WHERE question_id = $1', [qid]);
        await client.query('DELETE FROM accepted_answers WHERE question_id = $1', [qid]);
        await client.query('DELETE FROM questions WHERE id = $1', [qid]);
      }
    }

    await client.query('DELETE FROM quizzes WHERE id = $1', [quizId]);
    await client.query('COMMIT');
    res.json({ message: `Quiz deleted successfully${deleteQuestions === 'true' ? ' along with questions' : ''}` });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('deleteFullQuiz error:', err);
    res.status(500).json({ message: 'Failed to delete quiz' });
  } finally {
    client.release();
  }
};
