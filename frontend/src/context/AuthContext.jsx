import { createContext, useContext, useState, useEffect } from 'react';
import {
  loginUser,
  logoutUser,
  refreshToken,
  getProfile,
} from '../services/auth';

const AuthContext = createContext(); // Defined outside component for Fast Refresh

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // Initial loading while checking token

  const login = async (credentials) => {
    try {
      const userData = await loginUser(credentials);
      console.log(userData)
      setUser(userData);
    } catch (err) {
      throw err; // Let caller handle error (e.g. in login page)
    }
  };

  const logout = async () => {
    try {
      await logoutUser();
    } catch (err) {
      console.warn('Logout failed:', err);
    } finally {
      setUser(null);
    }
  };

  const fetchProfile = async () => {
    try {
      const profile = await getProfile();
      setUser(profile);
    } catch (err) {
      console.warn('Failed to fetch profile:', err);
      setUser(null);
    }
  };

  useEffect(() => {
    const initialize = async () => {
      try {
        await refreshToken(); // Try to refresh silently (via HttpOnly cookie)
        await fetchProfile(); // If successful, fetch user profile
      } catch (err) {
        setUser(null); // Not logged in
      } finally {
        setLoading(false); // Done loading
      }
    };

    initialize();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        loading,
        login,
        logout,
        fetchProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// Safer access to context
export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
};
