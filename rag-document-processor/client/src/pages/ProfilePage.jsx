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
    <div className="min-h-screen bg-slate-950 font-sans text-slate-200">
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
         <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full"></div>
      </div>
      
      <div className="relative z-10 max-w-3xl mx-auto p-6 md:p-12 pt-16">
        <button 
          onClick={() => navigate('/')}
          className="flex items-center gap-2 text-indigo-400 hover:text-indigo-300 transition-colors mb-8 font-medium text-sm"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Workspace
        </button>

        <header className="mb-8 border-b border-white/5 pb-6">
          <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
            <User className="w-8 h-8 text-indigo-400" />
            Profile Settings
          </h1>
          <p className="text-slate-400 mt-2 text-sm">Manage your identity and security preferences.</p>
        </header>

        {status.message && (
          <div className={"p-4 rounded-xl mb-6 text-sm font-medium border " + (status.type === 'error' ? 'bg-red-900/20 text-red-400 border-red-500/20' : 'bg-emerald-900/20 text-emerald-400 border-emerald-500/20')}>
            {status.message}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-8 glass-panel bg-slate-900/40 p-6 md:p-8 rounded-2xl border border-white/5 backdrop-blur-xl">
          
          <section>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
              <Shield className="w-4 h-4" /> Identity
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-slate-400 text-xs font-medium mb-1.5 uppercase tracking-wider">Email Address</label>
                <input
                  type="email"
                  value={user?.email || ''}
                  disabled
                  className="w-full px-4 py-2.5 bg-slate-900/50 border border-white/5 rounded-lg text-slate-500 cursor-not-allowed"
                />
                <p className="text-[10px] text-slate-500 mt-1">Email cannot be changed.</p>
              </div>
              <div>
                <label className="block text-slate-400 text-xs font-medium mb-1.5 uppercase tracking-wider">Username</label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 transition-colors"
                  minLength={3}
                  required
                />
              </div>
            </div>
          </section>

          <section className="pt-6 border-t border-white/5">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
              <Lock className="w-4 h-4" /> Security
            </h2>
            <div className="space-y-4 max-w-md">
              <div>
                <label className="block text-slate-400 text-xs font-medium mb-1.5 uppercase tracking-wider">Current Password *</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Required to save changes"
                  className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 transition-colors placeholder:text-slate-600"
                  required
                />
              </div>
              <div className="pt-2">
                <label className="block text-slate-400 text-xs font-medium mb-1.5 uppercase tracking-wider">New Password (Optional)</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Leave blank to keep current"
                  className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 transition-colors placeholder:text-slate-600"
                />
              </div>
              {newPassword && (
                <div>
                  <label className="block text-slate-400 text-xs font-medium mb-1.5 uppercase tracking-wider">Confirm New Password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full px-4 py-2.5 bg-slate-800/50 border border-white/5 rounded-lg text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 transition-colors"
                    required={!!newPassword}
                  />
                </div>
              )}
            </div>
          </section>

          <footer className="pt-6 border-t border-white/5 flex justify-end">
            <button 
              type="submit" 
              disabled={loading || !currentPassword}
              className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium shadow-[0_0_15px_rgba(79,70,229,0.3)] transition-all flex items-center gap-2 text-sm"
            >
              <Save className="w-4 h-4" />
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
          </footer>

        </form>
      </div>
    </div>
  );
};

export default ProfilePage;
