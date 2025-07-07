// routes/schoolRoutes.js
const express = require('express');
const router = express.Router();
const { getSchoolSuggestions } = require('../controllers/schoolController');

router.get('/', getSchoolSuggestions); // GET /api/schools?q=abc

module.exports = router;
