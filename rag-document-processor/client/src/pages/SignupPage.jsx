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
      <div className="min-h-screen flex items-center justify-center bg-[#060e20] font-sans relative overflow-hidden">
        <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full pointer-events-none"></div>
        <div className="relative z-10 max-w-md w-full glass-card p-12 rounded-[2.5rem] bg-[#0f192f]/40 text-center border border-white/5">
          <div className="w-20 h-20 bg-indigo-500/10 rounded-full flex items-center justify-center mx-auto mb-6 border border-indigo-500/20">
            <span className="text-3xl text-indigo-400">📬</span>
          </div>
          <h2 className="text-2xl font-bold text-white mb-3">Verification Required</h2>
          <p className="text-slate-400 mb-8 leading-relaxed">We've sent a secure access link to <br/><strong className="text-cyan-400 font-bold">{email}</strong>. <br/>Please confirm your identity to proceed.</p>
          <Link to="/login" className="btn-primary-gradient inline-block px-10 py-3.5 rounded-2xl font-bold text-sm tracking-wider shadow-xl transition-all">
            Return to Access Point
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#060e20] font-sans relative overflow-hidden">
      {/* Background Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full pointer-events-none"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-cyan-900/5 blur-[120px] rounded-full pointer-events-none"></div>

      <div className="relative z-10 max-w-md w-full glass-card p-10 rounded-[2.5rem] bg-[#0f192f]/40">
        <div className="text-center mb-8">
           <h1 className="text-3xl font-bold text-white tracking-tighter mb-2">Initialize Account</h1>
           <p className="text-xs uppercase tracking-[0.2em] text-slate-500 font-bold">New Security Principal</p>
        </div>

        {error && <p className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-2xl mb-6 text-xs font-medium text-center animate-shake">{error}</p>}
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-slate-500 text-[10px] font-bold mb-2 uppercase tracking-widest ml-1">Corporate Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@gmail.com"
              className="w-full input-glass px-5 py-3 rounded-2xl text-white placeholder:text-slate-600 focus:outline-none text-sm transition-all"
              required
            />
          </div>
          <div>
            <label className="block text-slate-500 text-[10px] font-bold mb-2 uppercase tracking-widest ml-1">Identity Display Name</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. John Doe"
              className="w-full input-glass px-5 py-3 rounded-2xl text-white placeholder:text-slate-600 focus:outline-none text-sm transition-all"
              minLength={3}
              required
            />
          </div>
          <div>
            <label className="block text-slate-500 text-[10px] font-bold mb-2 uppercase tracking-widest ml-1">Master Access Key</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full input-glass px-5 py-3 rounded-2xl text-white placeholder:text-slate-600 focus:outline-none text-sm transition-all"
              minLength={6}
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full btn-primary-gradient font-bold tracking-wider py-4 rounded-2xl transition-all shadow-xl disabled:opacity-30 disabled:cursor-not-allowed mt-4 text-sm"
          >
            {loading ? 'Processing...' : 'Register Identity'}
          </button>
        </form>

        <div className="mt-8 flex items-center justify-center space-x-4">
          <span className="h-px w-full bg-white/5"></span>
          <span className="text-slate-600 text-[10px] font-bold tracking-widest">OR</span>
          <span className="h-px w-full bg-white/5"></span>
        </div>

        <button
          onClick={handleGoogleSignup}
          disabled={loading}
          type="button"
          className="mt-8 w-full flex items-center justify-center gap-3 bg-white/5 border border-white/5 text-slate-300 py-3.5 rounded-2xl hover:bg-white/10 transition-all text-sm font-bold shadow-sm disabled:opacity-30"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
          </svg>
          Quick Sign Up with Google
        </button>

        <p className="text-center mt-8 text-slate-500 text-xs font-medium">
          Registered user? <Link to="/login" className="text-cyan-400 hover:text-cyan-300 transition-colors font-bold ml-1">Access Terminal</Link>
        </p>
      </div>
    </div>
  );
};

export default SignupPage;
