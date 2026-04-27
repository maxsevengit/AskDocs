import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';
import {
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendEmailVerification
} from 'firebase/auth';
import { auth, googleProvider } from '../config/firebase';

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

// Create a configured axios instance
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:3001',
});

// Add a request interceptor to include our app JWT in all requests
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    // Auto-logout if session is older than 8 hours
    const loginTime = localStorage.getItem('loginTime');
    if (loginTime && Date.now() - parseInt(loginTime) > 8 * 60 * 60 * 1000) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      localStorage.removeItem('loginTime');
      window.location.href = '/login';
      return Promise.reject(new Error('Session expired'));
    }
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Add a response interceptor to handle 401/403 (expired/invalid token)
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || error.response?.status === 403) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      localStorage.removeItem('loginTime');
      window.location.href = '/login';
    }
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
    if (user) localStorage.setItem('user', JSON.stringify(user));
    else localStorage.removeItem('user');
  }, [user]);

  // Helper: exchange a Firebase ID token for our app JWT
  const exchangeFirebaseToken = async (firebaseUser) => {
    const idToken = await firebaseUser.getIdToken();
    const response = await apiClient.post('/api/auth/firebase', { token: idToken });
    setToken(response.data.token);
    setUser(response.data.user);
    localStorage.setItem('loginTime', Date.now().toString());
    return response;
  };

  // Email + password sign-in via Firebase → backend
  const login = async (email, password) => {
    const cred = await signInWithEmailAndPassword(auth, email, password);
    if (!cred.user.emailVerified) {
      await auth.signOut();
      throw new Error('email-not-verified');
    }
    return exchangeFirebaseToken(cred.user);
  };

  // Email + password sign-UP via Firebase → sends verification email → NO backend call yet
  const signup = async (email, username, password) => {
    const cred = await createUserWithEmailAndPassword(auth, email, password);
    await sendEmailVerification(cred.user);
    // Store the desired username in localStorage so we can use it after verification
    localStorage.setItem('pendingUsername', username);
    // Sign the user out until they verify their email
    await auth.signOut();
    return { message: 'Verification email sent. Please check your inbox.' };
  };

  // Google OAuth → backend
  const loginWithGoogle = async () => {
    const result = await signInWithPopup(auth, googleProvider);
    return exchangeFirebaseToken(result.user);
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
    auth.signOut().catch(() => {});
    localStorage.removeItem('loginTime');
    setToken(null);
    setUser(null);
  };

  const value = {
    token, user, login, loginWithGoogle, signup, updateProfile, logout, apiClient,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
