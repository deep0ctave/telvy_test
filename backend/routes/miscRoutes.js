const express = require('express');
const router = express.Router();
const miscController = require('../controllers/miscController');

router.get('/help', miscController.getHelp);
router.post('/feedback', miscController.submitFeedback);
router.get('/languages', miscController.getLanguages);

router.get('/schools', miscController.getSchoolSuggestions);

module.exports = router;