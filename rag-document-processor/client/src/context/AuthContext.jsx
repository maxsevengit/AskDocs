import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

export const useAuth = () => useContext(AuthContext);

// Create a configured axios instance
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3001',
});

// Add a request interceptor to include the token in all requests
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user')) || null);

  useEffect(() => {
    if (token) {
      localStorage.setItem('token', token);
      if (!user) {
         apiClient.get('/api/auth/me')
           .then(res => setUser(res.data))
           .catch(() => { setToken(null); setUser(null); });
      }
    } else {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setUser(null);
    }
  }, [token]);

  useEffect(() => {
    if (user) {
      localStorage.setItem('user', JSON.stringify(user));
    } else {
      localStorage.removeItem('user');
    }
  }, [user]);

  const login = async (email, password) => {
    const response = await apiClient.post('/api/auth/login', { email, password });
    setToken(response.data.token);
    setUser(response.data.user);
    return response;
  };

  const signup = async (email, username, password) => {
    return apiClient.post('/api/auth/signup', { email, username, password });
  };

  const updateProfile = async (currentPassword, newUsername, newPassword) => {
    const response = await apiClient.put('/api/auth/profile', {
       currentPassword, newUsername, newPassword
    });
    if (response.data.token) {
       setToken(response.data.token);
       setUser(response.data.user);
    }
    return response;
  };

  const logout = () => {
    setToken(null);
    setUser(null);
  };

  const value = {
    token,
    user,
    login,
    signup,
    updateProfile,
    logout,
    apiClient, // Provide the configured axios instance
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
