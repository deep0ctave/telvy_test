const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authenticateJWT = require('../middlewares/auth/authenticateJWT');
const authorizeRoles = require('../middlewares/auth/authorizeRoles'); // ✅ your version
const validate = require('../middlewares/validationHandler');
const validators = require('../middlewares/validators/validationRules');

// 🧍 Regular User Routes
router.get('/profile', authenticateJWT, userController.getProfile);
router.put('/profile', authenticateJWT, validators.profileUpdateValidation,validate, userController.updateProfile);
router.post('/verify-phone-change', authenticateJWT, userController.verifyPhoneChange);
router.post('/verify-password-change', authenticateJWT, userController.verifyPasswordChange);

// 🛡️ Admin Routes (use 'admin' role string as per your DB)
router.get('/', authenticateJWT, authorizeRoles('admin'), userController.getAllUsers);
router.get('/:id', authenticateJWT, authorizeRoles('admin'), userController.getUserById);
router.put('/:id', authenticateJWT, authorizeRoles('admin'),validators.adminUserUpdateValidation,validate,userController.updateUserById);
router.delete('/:id', authenticateJWT, authorizeRoles('admin'), userController.deleteUser);
router.post('/',authenticateJWT,authorizeRoles('admin'),validators.adminUserCreateValidation,validate,userController.createUser);

module.exports = router;
