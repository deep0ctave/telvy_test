const { body } = require('express-validator');


const dobValidator = body('dob')
  .isDate().withMessage('Invalid date format')
  .custom((value) => {
    const dob = new Date(value);
    const now = new Date();

    if (dob > now) throw new Error('Date of birth cannot be in the future');

    const age = now.getFullYear() - dob.getFullYear();
    const isBeforeBirthday =
      now.getMonth() < dob.getMonth() ||
      (now.getMonth() === dob.getMonth() && now.getDate() < dob.getDate());
    const actualAge = isBeforeBirthday ? age - 1 : age;

    if (actualAge > 100) throw new Error('Age cannot be more than 100 years');
    if (actualAge < 5) throw new Error('Minimum age is 5');

    return true;
  });


// 🔹 Reusable password rule
const passwordField = (field = 'password') =>
  body(field)
    .isLength({ min: 8 }).withMessage(`${field} must be at least 8 characters`)
    .matches(/[A-Z]/).withMessage(`${field} must contain an uppercase letter`)
    .matches(/[a-z]/).withMessage(`${field} must contain a lowercase letter`)
    .matches(/\d/).withMessage(`${field} must contain a number`)
    .matches(/[@$!%*?&]/).withMessage(`${field} must contain a special character`);

// 🔸 Register
const registerValidation = [
  body('username').isAlphanumeric().isLength({ min: 3, max: 30 }).trim(),
  body('phone').isMobilePhone().withMessage('Invalid phone number').trim(),
  body('email').isEmail().normalizeEmail(),
  passwordField('password'),
  body('name').notEmpty().trim(),
  body('gender').isIn(['male', 'female', 'other']),
  dobValidator,
  body('school').notEmpty().trim(),
  body('class').notEmpty().trim(),
  body('section').notEmpty().trim(),
  body('user_type').isIn(['student', 'teacher', 'admin']),
];

// 🔸 Login
const loginValidation = [
  body('username').notEmpty().trim(),
  body('password').notEmpty()
];

// 🔸 OTP Verify (register)
const verifyOtpValidation = [
  body('phone').isMobilePhone(),
  body('otp').isLength({ min: 6, max: 6 })
];

// 🔸 Forgot Password Initiate
const forgotPasswordInitiateValidation = [
  body('phone').isMobilePhone()
];

// 🔸 Forgot Password Verify
const forgotPasswordVerifyValidation = [
  body('phone').isMobilePhone(),
  body('otp').isLength({ min: 6, max: 6 }),
  passwordField('new_password')
];

// 🔸 Resend OTPs
const resendOtpValidation = [
  body('phone').isMobilePhone()
];

const profileUpdateValidation = [
  body('username').not().exists().withMessage('Username cannot be changed'),
  body('user_type').not().exists().withMessage('User type cannot be changed'),
  body('is_verified').not().exists().withMessage('Verification status cannot be changed'),

  body('email').optional().isEmail().normalizeEmail(),
  body('phone')
    .optional()
    .isMobilePhone().withMessage('Invalid phone number')
    .notEmpty().withMessage('Phone number cannot be empty'),

  body('current_password')
    .notEmpty().withMessage('Current password is required'),

  body('new_password').optional(),
  body('old_password')
    .if(body('new_password').exists())
    .notEmpty().withMessage('Old password is required'),

  body('name').optional().trim().notEmpty(),
  body('gender').optional().isIn(['male', 'female', 'other']),
  body('dob').optional().isISO8601().withMessage('Invalid date format'),
  body('school').optional().notEmpty(),
  body('class').optional().notEmpty(),
  body('section').optional().notEmpty(),
];


const adminUserUpdateValidation = [
  body('username').not().exists().withMessage('Username cannot be updated'),
  body('password').not().exists().withMessage('Password cannot be updated here'),
  body('current_password').not().exists(),
  body('old_password').not().exists(),
  body('new_password').not().exists(),

  body('name').optional().trim().notEmpty(),
  body('email').optional().isEmail().normalizeEmail(),
  body('phone').optional().isMobilePhone().withMessage('Invalid phone number'),
  body('user_type').optional().isIn(['student', 'teacher', 'admin']),
  body('is_verified').optional().isBoolean(),

  body('gender').optional().isIn(['male', 'female', 'other']),
  body('dob').optional().isISO8601().withMessage('Invalid date format'),
  body('school').optional().notEmpty(),
  body('class').optional().notEmpty(),
  body('section').optional().notEmpty(),
];




// 🔸 Questions

const questionValidationRules = [
  body('question_text').isString().notEmpty().withMessage('Question text is required'),
  body('question_type')
    .isIn(['mcq', 'true_false', 'type_in'])
    .withMessage('Invalid question type'),
  body('tags').optional().isArray().withMessage('Tags must be an array'),
  body('question_image').optional().isURL().withMessage('Image must be a valid URL'),

  // For MCQ questions
  body('options').if(body('question_type').equals('mcq')).isArray({ min: 2 })
    .withMessage('MCQ must have at least 2 options'),
  body('options.*.text')
    .if(body('question_type').equals('mcq'))
    .notEmpty().withMessage('Each option must have text'),

  // For type-in questions
  body('accepted_answers')
    .if(body('question_type').equals('type_in'))
    .isArray({ min: 1 }).withMessage('Type-in must have at least one accepted answer'),
];

const adminUserCreateValidation = [
  body("username").notEmpty().withMessage("Username is required"),
  body("name").notEmpty().withMessage("Name is required"),
  body("phone").matches(/^\d{10}$/).withMessage("Enter valid 10-digit phone"),
  body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
  body("user_type").isIn(["student", "teacher", "admin"]),
];


module.exports = {
  registerValidation,
  loginValidation,
  verifyOtpValidation,
  forgotPasswordInitiateValidation,
  forgotPasswordVerifyValidation,
  resendOtpValidation,
  profileUpdateValidation,
  adminUserUpdateValidation,
  questionValidationRules,
  adminUserCreateValidation,
};

