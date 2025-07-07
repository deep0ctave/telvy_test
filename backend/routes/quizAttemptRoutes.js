const express = require('express');
const router = express.Router();
const attemptController = require('../controllers/attemptController');
const authenticateJWT = require('../middlewares/auth/authenticateJWT');

// Start a new quiz attempt
router.post('/start', authenticateJWT, attemptController.startQuizAttempt);

// Submit and finalize a quiz attempt
router.post('/submit', authenticateJWT, attemptController.submitQuizAttempt);

// Get a specific quiz attempt with questions
router.get('/:id', authenticateJWT, attemptController.getAttemptById);

// Get all attempts for a user
router.get('/user/:userId', authenticateJWT, attemptController.getAttemptsByUser);

module.exports = router;
