const pool = require('../db/client');

const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit
};

exports.sendOtp = async (phone, purpose = 'general') => {
  const otp = generateOtp();
  // Simulate SMS sending (log to console)
  console.log(`[OTP SENT] Phone: ${phone} | OTP: ${otp} | Purpose: ${purpose}`);

  return otp;
};
