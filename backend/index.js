const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const morgan = require('morgan');

const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const questionRoutes = require('./routes/questionRoutes');
const quizRoutes = require('./routes/quizRoutes');
const fullQuizRoutes = require('./routes/quizFullRoutes');
const attemptRoutes = require('./routes/attemptRoutes');
const adminRoutes = require('./routes/adminRoutes');
const miscRoutes = require('./routes/miscRoutes');

const errorHandler = require('./middlewares/errorHandler');


dotenv.config(); // Load environment variables

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
// ✅ CORS — must be early
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://telvy-test.vercel.app',
    'https://telvy-test-2v0err1bd-deep0ctaves-projects.vercel.app'
  ],
  credentials: true,
}));

// ✅ Allow preflight OPTIONS requests
app.options('*', cors());

const cookieParser = require('cookie-parser');
app.use(cookieParser());

app.use(express.json());
app.use(morgan('dev'));

// Route Mounting
console.log('Mounting /api/auth...');
app.use('/api/auth', authRoutes);

console.log('Mounting /api/users...');
app.use('/api/users', userRoutes);

console.log('Mounting /api/questions...');
app.use('/api/questions', questionRoutes);

console.log('Mounting /api/quizzes...');
app.use('/api/quizzes', quizRoutes);

console.log('Mounting /api/attempts...');
app.use('/api/attempts', attemptRoutes);

console.log('Mounting /api/admin...');
app.use('/api/admin', adminRoutes);

console.log('Mounting /api/misc...');
app.use('/api/misc', miscRoutes);

console.log('Mounting /api/full-quizzes...');
app.use('/api/full-quizzes', fullQuizRoutes);




// Fallback Route
app.use('*splat', (req, res) => {
  res.status(404).json({ error: 'Route not found buddy' });
});

// Global error handler
app.use(errorHandler);

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
