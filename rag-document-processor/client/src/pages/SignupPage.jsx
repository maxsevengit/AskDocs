import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';

const SignupPage = () => {
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const { signup, loginWithGoogle } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Enforce Gmail-only before even calling Firebase
    if (!email.endsWith('@gmail.com') && !email.endsWith('@googlemail.com')) {
      setError('Only @gmail.com addresses are allowed. Please use your Google account.');
      return;
    }

    setLoading(true);
    try {
      await signup(email, username, password);
      setSuccess(true);
    } catch (err) {
      if (err.code === 'auth/email-already-in-use') {
        setError('An account with this email already exists.');
      } else if (err.code === 'auth/invalid-email') {
        setError('Please enter a valid email address.');
      } else if (err.code === 'auth/weak-password') {
        setError('Password should be at least 6 characters.');
      } else {
        setError(err.response?.data?.error || err.message || 'Failed to sign up.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignup = async () => {
    setError('');
    setLoading(true);
    try {
      await loginWithGoogle();
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to sign up with Google.');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 font-sans">
        <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
          <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full"></div>
        </div>
        <div className="relative z-10 max-w-md w-full bg-slate-900/40 p-10 rounded-xl border border-white/5 backdrop-blur-xl text-center">
          <div className="text-5xl mb-5">📬</div>
          <h2 className="text-2xl font-bold text-white mb-3">Check Your Inbox!</h2>
          <p className="text-slate-400 mb-6">We sent a verification link to <strong className="text-indigo-300">{email}</strong>. Click it to activate your account.</p>
          <p className="text-slate-500 text-sm">After verifying, you can log in below.</p>
          <Link to="/login" className="mt-6 inline-block bg-indigo-600 text-white px-8 py-2.5 rounded-xl font-medium hover:bg-indigo-500 transition-colors">
            Go to Login →
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 font-sans">
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full"></div>
      </div>
      <div className="relative z-10 max-w-md w-full bg-slate-900/40 p-8 rounded-xl shadow-[0_0_15px_rgba(0,0,0,0.5)] border border-white/5 backdrop-blur-xl">
        <h2 className="text-2xl font-bold text-center mb-6 text-white tracking-tight">Create Account</h2>
        {error && <p className="bg-red-900/40 border border-red-500/20 text-red-400 p-3 rounded-lg mb-4 text-sm font-medium">{error}</p>}
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-slate-400 text-sm font-medium mb-1.5 uppercase tracking-wider">Email (Gmail only)</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors"
              required
            />
          </div>
          <div className="mb-4">
            <label className="block text-slate-400 text-sm font-medium mb-1.5 uppercase tracking-wider">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors"
              minLength={3}
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
              minLength={6}
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-indigo-600 font-medium tracking-wide text-white py-2.5 rounded-lg hover:bg-indigo-500 transition-colors shadow-[0_0_15px_rgba(79,70,229,0.3)] disabled:opacity-50"
          >
            {loading ? 'Creating account...' : 'Sign Up'}
          </button>
        </form>

        <div className="mt-6 flex items-center justify-center space-x-2">
          <span className="h-px w-full bg-white/10"></span>
          <span className="text-slate-500 text-sm font-medium">OR</span>
          <span className="h-px w-full bg-white/10"></span>
        </div>

        <button
          onClick={handleGoogleSignup}
          disabled={loading}
          type="button"
          className="mt-6 w-full flex items-center justify-center gap-3 bg-white text-slate-900 py-2.5 rounded-xl hover:bg-slate-100 transition-colors font-medium shadow-md disabled:opacity-50"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
          </svg>
          Continue with Google
        </button>

        <p className="text-center mt-5 text-slate-400 text-sm">
          Already have an account? <Link to="/login" className="text-indigo-400 hover:text-indigo-300 transition-colors font-medium">Log in</Link>
        </p>
      </div>
    </div>
  );
};

export default SignupPage;
