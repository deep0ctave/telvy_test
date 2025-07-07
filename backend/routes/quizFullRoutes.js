// routes/quizFullRoutes.js
const express = require('express');
const router = express.Router();
const authenticateJWT = require('../middlewares/auth/authenticateJWT');
const authorizeRoles = require('../middlewares/auth/authorizeRoles');
const fullController = require('../controllers/quizFullController');

router.post(
  '/',
  authenticateJWT,
  authorizeRoles('admin', 'teacher'),
  fullController.createFullQuiz
);

router.get(
  '/',
  authenticateJWT,
  authorizeRoles('admin', 'teacher'),
  fullController.getAllFullQuizzes
);

router.get(
  '/:quizId',
  authenticateJWT,
  fullController.getFullQuiz
);

router.put(
  '/:quizId',
  authenticateJWT,
  authorizeRoles('admin', 'teacher'),
  fullController.updateFullQuiz
);

router.delete(
  '/:quizId',
  authenticateJWT,
  authorizeRoles('admin', 'teacher'),
  fullController.deleteFullQuiz
);

module.exports = router;
