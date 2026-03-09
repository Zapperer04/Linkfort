import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);
const API_BASE = 'http://localhost:5000';

// Set token in axios headers globally
const setAxiosToken = (token) => {
  if (token) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    delete axios.defaults.headers.common['Authorization'];
  }
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // On app load, check if token exists in localStorage
    const savedToken = localStorage.getItem('linkfort_token');
    
    if (savedToken) {
      setAxiosToken(savedToken);  // Set header immediately
      fetchCurrentUser();
    } else {
      setLoading(false);
    }
  }, []);

  const fetchCurrentUser = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/auth/me`);
      setUser(response.data.user);
    } catch (error) {
      console.error('Auth check failed:', error.response?.status);
      // Token invalid or expired - clear it
      localStorage.removeItem('linkfort_token');
      setAxiosToken(null);
      setUser(null);
    }
    setLoading(false);
  };

  const login = async (email, password) => {
    const response = await axios.post(`${API_BASE}/api/auth/login`, {
      email,
      password
    });
    
    const { access_token, user } = response.data;
    
    // Save token and set headers
    localStorage.setItem('linkfort_token', access_token);
    setAxiosToken(access_token);
    setUser(user);
    
    return response.data;
  };

  const register = async (username, email, password) => {
    const response = await axios.post(`${API_BASE}/api/auth/register`, {
      username,
      email,
      password
    });
    
    const { access_token, user } = response.data;
    
    // Save token and set headers
    localStorage.setItem('linkfort_token', access_token);
    setAxiosToken(access_token);
    setUser(user);
    
    return response.data;
  };

  const logout = async () => {
    try {
      await axios.post(`${API_BASE}/api/auth/logout`);
    } catch (e) {}
    
    localStorage.removeItem('linkfort_token');
    setAxiosToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}