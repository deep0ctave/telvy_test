import api from './api';

export const loginUser = async ({ username, password, force = false }) => {
  const res = await api.post('/auth/login', { username, password, force });
  const { accessToken, user } = res.data;
  console.log(res.data)
  localStorage.setItem('accessToken', accessToken);
  return user;
};

export const logoutUser = async () => {
  try {
    await api.post('/auth/logout');
  } catch (err) {
    console.error('[Logout Error]', err);
  } finally {
    localStorage.removeItem('accessToken');
  }
};

export const refreshToken = async () => {
  const res = await api.post('/auth/refresh');
  const { accessToken } = res.data;
  if (accessToken) {
    localStorage.setItem('accessToken', accessToken);
    return accessToken;
  } else {
    throw new Error('Failed to refresh token');
  }
};

export const getProfile = async () => {
  const res = await api.get('/users/profile');
  return res.data;
};

export const registerUser = async (formData) => {
  const res = await api.post('/auth/register/initiate', {
    username: formData.username,
    phone: formData.phone,
    email: formData.email,
    password: formData.password,
    name: formData.name,
    gender: formData.gender,
    dob: formData.dob,
    school: formData.school,
    class: formData.class,
    section: formData.section,
    user_type: formData.user_type,
  });
  return res.data;
};

export const verifyOtp = async ({ phone, otp }) => {
  const res = await api.post('/auth/register/verify-otp', { phone, otp });
  return res.data;
};

export const resendOtp = async (phone) => {
  const res = await api.post('/auth/register/resend', { phone });
  return res.data;
};