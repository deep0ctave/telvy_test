import axios from 'axios';

// Create a pre-configured Axios instance
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true, // send cookies including refreshToken
});

let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) prom.reject(error);
    else prom.resolve(token);
  });
  failedQueue = [];
};

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const original = err.config;

    if (err.response?.status === 401 && !original._retry) {
      original._retry = true;

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          original.headers.Authorization = `Bearer ${token}`;
          return api(original);
        });
      }

      isRefreshing = true;

      try {
        const { data } = await axios.post(
          `${import.meta.env.VITE_API_URL}/auth/refresh`,
          {},
          { withCredentials: true }
        );
        const newAccessToken = data.accessToken;

        localStorage.setItem('accessToken', newAccessToken);
        api.defaults.headers.common['Authorization'] = `Bearer ${newAccessToken}`;
        processQueue(null, newAccessToken);

        original.headers.Authorization = `Bearer ${newAccessToken}`;
        return api(original);
      } catch (refreshError) {
        processQueue(refreshError, null);
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(err);
  }
);


export const fetchSchoolSuggestions = async (query) => {
  if (!query.trim()) return [];
  try {
    const res = await api.get(`/misc/schools?q=${encodeURIComponent(query)}`);
    return res.data.schools || [];
  } catch (err) {
    console.error('School fetch error:', err);
    return [];
  }
};

export const getAllFullQuizzes = async () => {
  const res = await api.get('/full-quizzes');
  return res.data;
};

export const createFullQuiz = (payload) =>
  api.post('/full-quizzes', payload);

export const getFullQuiz = (quizId) =>
  api.get(`/full-quizzes/${quizId}`);

export const updateFullQuiz = (quizId, payload) =>
  api.put(`/full-quizzes/${quizId}`, payload);

export const deleteFullQuiz = (quizId, withQuestions = true) =>
  api.delete(`/full-quizzes/${quizId}?deleteQuestions=${withQuestions}`);

// 🔹 Create user
export const createUser = async (data) => {
  return api.post('/users', data); // You may need to hit /users/admin or adjust the path if required
};

// 🔸 Get all users
export const getAllUsers = async () => {
  const res = await api.get('/users');
  return res.data.users;
};

// 🔸 Get a single user
export const getUserById = async (id) => {
  const res = await api.get(`/users/${id}`);
  return res.data.user;
};

// ✏️ Update user (admin)
export const updateUserById = async (id, data) => {
  return api.put(`/users/${id}`, data);
};

// ❌ Delete user
export const deleteUserById = async (id) => {
  return api.delete(`/users/${id}`);
};


// ✅ Log all requests
api.interceptors.request.use((config) => {
  console.log('[API Request]', config.method?.toUpperCase(), config.url, config.data || {});
  return config;
}, (error) => {
  console.error('[API Request Error]', error);
  return Promise.reject(error);
});

// ✅ Log all responses
api.interceptors.response.use((response) => {
  console.log('[API Response]', response.config.url, response.data);
  return response;
}, (error) => {
  console.error('[API Response Error]', error.response?.config?.url, error.response?.data);
  return Promise.reject(error);
});

export default api;
