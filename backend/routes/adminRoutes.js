const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');

router.get('/users', adminController.getAllUsers);
router.get('/quizzes', adminController.getAllQuizzes);
router.get('/stats', adminController.getPlatformStats);

module.exports = router;