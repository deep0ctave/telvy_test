const express = require('express');
const router = express.Router();

const questionController = require('../controllers/questionController');
const authenticateJWT = require('../middlewares/auth/authenticateJWT');
const authorizeRoles = require('../middlewares/auth/authorizeRoles');
const validate = require('../middlewares/validationHandler');
const validators = require('../middlewares/validators/validationRules');

// Get all questions (Authenticated)
router.get('/',authenticateJWT,questionController.getAllQuestions);

// Get question by ID (Authenticated)
router.get('/:id',authenticateJWT,questionController.getQuestionById);

// Create question (Authenticated + Role: admin or teacher)
router.post('/',authenticateJWT,authorizeRoles('admin', 'teacher'),validators.questionValidationRules,validate,questionController.createQuestion);

// Update question (Authenticated + Role: admin or owner teacher)
router.put('/:id',authenticateJWT,authorizeRoles('admin', 'teacher'),validators.questionValidationRules,validate,questionController.updateQuestion);

// Delete question (Authenticated + Role: admin or owner teacher)
router.delete('/:id',authenticateJWT,authorizeRoles('admin', 'teacher'),questionController.deleteQuestion);

module.exports = router;
