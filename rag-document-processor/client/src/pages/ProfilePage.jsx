import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { User, Lock, Save, Shield, ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const ProfilePage = () => {
  const { user, updateProfile } = useAuth();
  const navigate = useNavigate();
  
  const [currentPassword, setCurrentPassword] = useState('');
  const [newUsername, setNewUsername] = useState(user?.username || '');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [status, setStatus] = useState({ type: '', message: '' });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus({ type: '', message: '' });

    if (!currentPassword) {
      return setStatus({ type: 'error', message: 'Current password is required to save changes.' });
    }
    
    if (newPassword && newPassword !== confirmPassword) {
      return setStatus({ type: 'error', message: 'New passwords do not match.' });
    }

    if (newPassword && newPassword.length < 6) {
      return setStatus({ type: 'error', message: 'New password must be at least 6 characters.' });
    }

    setLoading(true);
    try {
      await updateProfile(currentPassword, newUsername, newPassword);
      setStatus({ type: 'success', message: 'Profile updated successfully!' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setStatus({ type: 'error', message: err.response?.data?.error || 'Failed to update profile.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#060e20] font-sans text-slate-200 relative overflow-hidden">
      {/* Background Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full pointer-events-none"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-cyan-900/5 blur-[120px] rounded-full pointer-events-none"></div>
      
      <div className="relative z-10 max-w-3xl mx-auto p-6 md:p-12 pt-16">
        <button 
          onClick={() => navigate('/')}
          className="group flex items-center gap-2 text-slate-500 hover:text-cyan-400 transition-all mb-10 font-bold text-[10px] uppercase tracking-widest"
        >
          <ArrowLeft className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-1" /> Return to Intelligence Terminal
        </button>

        <header className="mb-12">
          <div className="flex items-center gap-4 mb-3">
             <div className="w-12 h-12 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
                <User className="w-6 h-6 text-indigo-400" />
             </div>
             <h1 className="text-4xl font-bold text-white tracking-tighter">Security Profile</h1>
          </div>
          <p className="text-slate-500 text-sm font-medium ml-1">Manage your administrative identity and access protocols.</p>
        </header>

        {status.message && (
          <div className={"p-5 rounded-[1.5rem] mb-8 text-xs font-bold border flex items-center gap-3 animate-slide-in " + (status.type === 'error' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20')}>
            <div className={`w-2 h-2 rounded-full ${status.type === 'error' ? 'bg-red-500' : 'bg-emerald-500'} animate-pulse`} />
            {status.message}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-10 glass-card bg-[#0f192f]/40 p-8 md:p-10 rounded-[2.5rem]">
          
          <section>
            <h2 className="text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500 mb-6 flex items-center gap-3">
              <Shield className="w-3.5 h-3.5 text-cyan-500" /> Identity Matrix
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div>
                <label className="block text-slate-500 text-[10px] font-bold mb-2.5 uppercase tracking-widest ml-1">System Identifier</label>
                <input
                  type="email"
                  value={user?.email || ''}
                  disabled
                  className="w-full input-glass px-5 py-3.5 rounded-2xl text-slate-500 bg-white/[0.02] border-white/5 cursor-not-allowed text-sm"
                />
                <p className="text-[10px] text-slate-600 mt-2 ml-1 italic">Identifier is immutable.</p>
              </div>
              <div>
                <label className="block text-slate-500 text-[10px] font-bold mb-2.5 uppercase tracking-widest ml-1">Public Handle</label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full input-glass px-5 py-3.5 rounded-2xl text-white focus:outline-none text-sm transition-all"
                  minLength={3}
                  required
                />
              </div>
            </div>
          </section>

          <section className="pt-10 border-t border-white/5">
            <h2 className="text-[10px] font-bold uppercase tracking-[0.25em] text-slate-500 mb-6 flex items-center gap-3">
              <Lock className="w-3.5 h-3.5 text-indigo-500" /> Access Verification
            </h2>
            <div className="space-y-6 max-w-md">
              <div>
                <label className="block text-slate-500 text-[10px] font-bold mb-2.5 uppercase tracking-widest ml-1">Active Access Key</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Required for authorization"
                  className="w-full input-glass px-5 py-3.5 rounded-2xl text-white focus:outline-none text-sm transition-all placeholder:text-slate-700"
                  required
                />
              </div>
              <div className="pt-2">
                <label className="block text-slate-500 text-[10px] font-bold mb-2.5 uppercase tracking-widest ml-1">New Access Key (Optional)</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Leave empty to maintain"
                  className="w-full input-glass px-5 py-3.5 rounded-2xl text-white focus:outline-none text-sm transition-all placeholder:text-slate-700"
                />
              </div>
              {newPassword && (
                <div className="animate-fade-in">
                  <label className="block text-slate-500 text-[10px] font-bold mb-2.5 uppercase tracking-widest ml-1">Confirm New Key</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full input-glass px-5 py-3.5 rounded-2xl text-white focus:outline-none text-sm transition-all"
                    required={!!newPassword}
                  />
                </div>
              )}
            </div>
          </section>

          <footer className="pt-10 border-t border-white/5 flex justify-end">
            <button 
              type="submit" 
              disabled={loading || !currentPassword}
              className="px-10 py-4 btn-primary-gradient disabled:opacity-20 disabled:cursor-not-allowed rounded-2xl font-bold tracking-widest transition-all shadow-xl flex items-center gap-3 text-xs"
            >
              <Save className="w-4 h-4" />
              {loading ? 'Committing...' : 'Commit Changes'}
            </button>
          </footer>

        </form>
      </div>
    </div>
  );
};

export default ProfilePage;
