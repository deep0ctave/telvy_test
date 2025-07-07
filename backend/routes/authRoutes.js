const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');
const validate = require('../middlewares/validationHandler');
const validators = require('../middlewares/validators/validationRules');
const authenticateJWT = require('../middlewares/auth/authenticateJWT');

// 🔹 Register
router.post('/register/initiate', validators.registerValidation, validate, authController.registerInitiate);
router.post('/register/verify-otp', validators.verifyOtpValidation, validate, authController.registerVerify);
router.post('/register/resend', validators.resendOtpValidation, validate, authController.resendOtp);

// 🔹 Login
router.post('/login', validators.loginValidation, validate, authController.login);

// 🔹 Logout
router.post('/logout', authenticateJWT, authController.logout);

// 🔹 Forgot Password
router.post('/forgot-password/initiate', validators.forgotPasswordInitiateValidation, validate, authController.forgotPasswordInitiate);
router.post('/forgot-password/verify', validators.forgotPasswordVerifyValidation, validate, authController.forgotPasswordVerify);
router.post('/forgot-password/resend', validators.resendOtpValidation, validate, authController.forgotPasswordResend);

// 🔹 Request new Refresh Token
router.post('/refresh',authController.refreshToken);

module.exports = router;
