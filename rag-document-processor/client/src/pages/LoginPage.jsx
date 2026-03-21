import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';

const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      setError('Failed to log in. Please check your credentials.');
      console.error('Login error:', err);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 font-sans">
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
         <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full"></div>
      </div>
      <div className="relative z-10 max-w-md w-full bg-slate-900/40 p-8 rounded-xl border border-white/5 backdrop-blur-xl">
        <h2 className="text-2xl font-bold text-center mb-6 text-white tracking-tight">Login</h2>
        {error && <p className="bg-red-900/40 border border-red-500/20 text-red-400 p-3 rounded-lg mb-4 text-sm font-medium">{error}</p>}
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-slate-400 text-sm font-medium mb-1.5 uppercase tracking-wider">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors"
              required
            />
          </div>
          <div className="mb-6">
            <label className="block text-slate-400 text-sm font-medium mb-1.5 uppercase tracking-wider">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors"
              required
            />
          </div>
          <button type="submit" className="w-full bg-indigo-600 font-medium tracking-wide text-white py-2.5 rounded-xl hover:bg-indigo-500 transition-colors shadow-[0_0_15px_rgba(79,70,229,0.3)]">
            Login
          </button>
        </form>
        <p className="text-center mt-6 text-slate-400 text-sm">
          Don't have an account? <Link to="/signup" className="text-indigo-400 hover:text-indigo-300 transition-colors font-medium">Sign up</Link>
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
