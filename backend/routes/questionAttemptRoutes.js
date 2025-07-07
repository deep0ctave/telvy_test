const express = require('express');
const router = express.Router();
const authenticateJWT = require('../middlewares/auth/authenticateJWT');
const attemptController = require('../controllers/attemptController');

// Question attempt routes
router.post('/submit', authenticateJWT, attemptController.submitQuestionAttempt);
router.put('/:id', authenticateJWT, attemptController.updateQuestionAttempt); // optional
router.get('/quiz/:quizAttemptId', authenticateJWT, attemptController.getQuestionAttemptsByQuizAttemptId);
router.get('/:id', authenticateJWT, attemptController.getQuestionAttemptById); // optional

module.exports = router;
