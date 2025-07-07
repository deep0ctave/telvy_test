const db = require('../db/client');

exports.getAllUsers = async (req, res) => {
  res.json({ message: 'Admin: get all users' });
};

exports.getAllQuizzes = async (req, res) => {
  res.json({ message: 'Admin: get all quizzes' });
};

exports.getPlatformStats = async (req, res) => {
  res.json({ message: 'Admin: get platform stats' });
};