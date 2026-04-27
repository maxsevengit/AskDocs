import React, { useState, useRef, useEffect } from 'react';
import { Routes, Route, Navigate, Link } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import ProfilePage from './pages/ProfilePage';
import HistoryItem from './components/HistoryItem';
import { CheckCircle, XCircle, Send, FileText, Upload, Trash2, Eye, LogOut, User } from 'lucide-react';
import { TailSpin } from 'react-loader-spinner';

// Wrapper for protected routes
const ProtectedRoute = ({ children }) => {
  const { token } = useAuth();
  return token ? children : <Navigate to="/login" />;
};

// Main application component, now protected
const MainApp = () => {
  const { apiClient, logout, user } = useAuth();

  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [response, setResponse] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const fileInputRef = useRef(null);
  const [queryHistory, setQueryHistory] = useState([]);

  const loadQueryHistory = async () => {
    try {
      const response = await apiClient.get('/api/query-history');
      setQueryHistory(response.data.reverse()); // Show newest first
    } catch (error) {
      console.error('Failed to load query history:', error);
    }
  };

  const handleProcessQuery = async () => {
    if (!query.trim()) {
      setError('Please enter a query');
      return;
    }

    setLoading(true);
    setError('');
    // We don't clear response immediately to allow a smooth transition
    // but we can clear it if we want a fresh start
    // setResponse(null); 

    try {
      const result = await apiClient.post('/api/process-query', {
        query: query.trim()
      });

      setResponse(result.data);
      await loadQueryHistory(); // Refresh history
    } catch (err) {
      console.error('Error processing query:', err);
      if (err.response?.data?.error) {
        setError(err.response.data.error);
      } else if (err.code === 'ERR_NETWORK_ERROR') {
        setError('Unable to connect to server. Please ensure the backend is running.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !loading) {
      handleProcessQuery();
    }
  };

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setUploading(true);
    setUploadProgress(0);

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        // Check file type
        const allowedTypes = ['application/pdf', 'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'message/rfc822'];
        const allowedExtensions = ['.pdf', '.txt', '.docx', '.eml'];
        const fileExtension = `.${file.name.split('.').pop()}`;

        if (!allowedTypes.includes(file.type) && !allowedExtensions.includes(fileExtension)) {
          throw new Error(`Unsupported file type: ${file.type || 'unknown'}. Please upload PDF, TXT, DOCX, or EML files only.`);
        }

        const formData = new FormData();
        formData.append('document', file);

        // Upload document to backend
        const uploadResponse = await apiClient.post('/api/documents/upload', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
          onUploadProgress: (progressEvent) => {
            const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            setUploadProgress(progress);
          }
        });

        // Add to documents list
        setDocuments(prev => [...prev, {
          id: uploadResponse.data.id,
          name: file.name,
          type: file.type,
          size: file.size,
          uploadedAt: new Date().toISOString()
        }]);

        setUploadProgress((i + 1) * (100 / files.length));
      }

      // Refresh documents list
      await loadDocuments();
      
    } catch (error) {
      console.error('Upload error:', error);
      setError(error.response?.data?.error || error.message || 'Failed to upload document');
    } finally {
      setUploading(false);
      setUploadProgress(0);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const loadDocuments = async () => {
    try {
      const response = await apiClient.get('/api/documents');
      setDocuments(response.data);
    } catch (error) {
      console.error('Failed to load documents:', error);
    }
  };

  const deleteDocument = async (documentId) => {
    try {
      await apiClient.delete(`/api/documents/${documentId}`);
      setDocuments(prev => prev.filter(doc => doc.id !== documentId));
    } catch (error) {
      console.error('Failed to delete document:', error);
      setError('Failed to delete document');
    }
  };

  const handleDeleteHistoryItem = async (id) => {
    try {
      await apiClient.delete(`/api/query-history/${id}`);
      await loadQueryHistory(); // Refresh the list
    } catch (error) {
      console.error('Failed to delete query from history:', error);
      setError('Failed to delete history item.');
    }
  };

  const viewDocument = async (documentId) => {
    try {
      const response = await apiClient.get(`/api/documents/${documentId}/content`);
      alert(`Document Content:\n\n${response.data.content}`);
    } catch (error) {
      console.error('Failed to view document:', error);
      setError('Failed to load document content');
    }
  };

  // Load documents and query history on component mount
  useEffect(() => {
    loadDocuments();
    loadQueryHistory();
  }, []);

  return (
    <div className="flex h-screen bg-[#060e20] font-sans text-[#dde5ff] overflow-hidden">
      {/* 1. Left Sidebar: Navigation & Document Management */}
      <aside className="w-80 glass-panel flex flex-col border-r border-white/5 shrink-0">
        <div className="p-6 border-b border-white/5">
          <div className="flex items-center gap-3 mb-6">
            <div className="bg-cyan-500/10 p-2.5 rounded-xl border border-cyan-500/20">
              <FileText className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">Accounting AI</h1>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Financial Intelligence</p>
            </div>
          </div>

          <div className="space-y-1">
             <Link to="/profile" className="flex items-center gap-3 p-3 rounded-xl hover:bg-white/5 transition-all text-sm font-medium text-slate-400 hover:text-white">
                <User className="w-4 h-4" /> Profile
             </Link>
             <button onClick={logout} className="w-full flex items-center gap-3 p-3 rounded-xl hover:bg-red-500/5 transition-all text-sm font-medium text-slate-400 hover:text-red-400">
                <LogOut className="w-4 h-4" /> Sign Out
             </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-6">
          {/* Upload Area */}
          <div>
            <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-4 px-2">Knowledge Base</h3>
            <div 
              className={`p-4 rounded-2xl border border-dashed border-cyan-500/30 bg-cyan-500/5 hover:bg-cyan-500/10 transition-all cursor-pointer text-center group ${uploading ? 'opacity-50' : ''}`}
              onClick={() => !uploading && fileInputRef.current?.click()}
            >
              <Upload className="w-6 h-6 text-cyan-400 mx-auto mb-2 group-hover:scale-110 transition-transform" />
              <p className="text-xs font-semibold text-cyan-300">Upload Standards</p>
              <p className="text-[10px] text-slate-500 mt-1">PDF, DOCX, TXT, EML</p>
              <input ref={fileInputRef} type="file" multiple hidden onChange={handleFileUpload} />
              
              {uploading && (
                <div className="mt-3 w-full bg-slate-800 rounded-full h-1 overflow-hidden">
                  <div className="bg-cyan-400 h-full transition-all" style={{ width: `${uploadProgress}%` }}></div>
                </div>
              )}
            </div>
          </div>

          {/* Documents List */}
          <div>
            <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-3 px-2">Source Library ({documents.length})</h3>
            <div className="space-y-2">
              {documents.map((doc) => (
                <div key={doc.id} className="group flex items-center justify-between p-3 rounded-xl bg-white/5 border border-white/5 hover:border-cyan-500/30 transition-all">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-slate-300 truncate">{doc.name}</p>
                    <p className="text-[10px] text-slate-500 mt-0.5">{(doc.size / 1024).toFixed(1)} KB</p>
                  </div>
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => viewDocument(doc.id)} className="p-1.5 text-slate-400 hover:text-cyan-400"><Eye className="w-3.5 h-3.5" /></button>
                    <button onClick={() => deleteDocument(doc.id)} className="p-1.5 text-slate-400 hover:text-red-400"><Trash2 className="w-3.5 h-3.5" /></button>
                  </div>
                </div>
              ))}
              {documents.length === 0 && <p className="text-[10px] text-slate-600 italic text-center py-4">No documents uploaded.</p>}
            </div>
          </div>
        </div>

        {/* User Badge */}
        <div className="p-4 border-t border-white/5 bg-black/20">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-white/5 border border-white/5">
            <div className="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center text-xs font-bold text-white uppercase">
              {user?.username?.charAt(0) || 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-bold text-white truncate">{user?.username}</p>
              <p className="text-[10px] text-slate-500 truncate">{user?.email}</p>
            </div>
          </div>
        </div>
      </aside>

      {/* 2. Center: AI Chat Interface */}
      <main className="flex-1 flex flex-col relative bg-[#060e20]">
        {/* Background Glow */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-4xl h-96 bg-indigo-900/10 blur-[120px] rounded-full pointer-events-none"></div>

        {/* Chat Header */}
        <header className="p-6 flex justify-between items-center z-10">
          <h2 className="text-lg font-bold text-white">Assistant Intelligence</h2>
          <div className="flex gap-2">
             <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full border border-emerald-500/20">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></div> System Ready
             </span>
          </div>
        </header>

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-8 z-10 scroll-smooth">
          {response ? (
            <div className="max-w-4xl mx-auto space-y-8">
              {/* Question */}
              <div className="flex justify-end">
                <div className="glass-card p-4 rounded-2xl max-w-[80%] surface-high">
                  <p className="text-sm text-slate-200">{query}</p>
                </div>
              </div>

              {/* Answer */}
              <div className="flex justify-start animate-slide-up">
                <div className="glass-card p-6 rounded-2xl max-w-[90%] neon-border-left bg-[#0f192f]/60 relative overflow-hidden group">
                  <div className="absolute top-0 right-0 p-4 opacity-10">
                    <FileText className="w-12 h-12 text-cyan-400" />
                  </div>
                  <h4 className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold mb-4">AI Analysis Report</h4>
                  <div className="text-slate-200 leading-relaxed text-base whitespace-pre-wrap">
                    {response.answer}
                  </div>

                  {/* Confidence Badge */}
                  <div className="mt-6 flex items-center gap-3">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Confidence:</span>
                    <span className={`text-[10px] font-bold px-3 py-1 rounded-full border ${
                      response.confidence === 'high' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                      'bg-amber-500/10 text-amber-400 border-amber-500/20'
                    }`}>
                      {response.confidence?.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center opacity-40">
               <div className="w-24 h-24 rounded-full bg-indigo-500/5 flex items-center justify-center mb-6 border border-indigo-500/10 pulse-secondary">
                  <Send className="w-8 h-8 text-indigo-400" />
               </div>
               <h3 className="text-xl font-bold text-white mb-2">How can I assist with reporting standards?</h3>
               <p className="text-sm max-w-md mx-auto text-slate-400 leading-relaxed">
                 Ask questions about IFRS, GAAP, or your internal accounting policies. I'll analyze your knowledge base to provide cited answers.
               </p>
            </div>
          )}
          
          {loading && (
            <div className="flex justify-start max-w-4xl mx-auto">
              <div className="glass-card p-6 rounded-2xl flex items-center gap-4">
                <TailSpin color="#00ffff" height={24} width={24} />
                <p className="text-sm text-cyan-300 font-medium animate-pulse">Deep scanning knowledge base...</p>
              </div>
            </div>
          )}

          {error && (
            <div className="max-w-4xl mx-auto">
               <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-4 flex items-start gap-3">
                  <XCircle className="w-5 h-5 text-red-400 shrink-0" />
                  <div>
                    <p className="text-sm font-bold text-red-400">Analysis Halted</p>
                    <p className="text-xs text-red-300/70 mt-1">{error}</p>
                  </div>
               </div>
            </div>
          )}
        </div>

        {/* Input Bar */}
        <div className="p-6 z-10">
           <div className="max-w-4xl mx-auto relative group">
              <textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Query accounting standards or policies..."
                className="w-full input-glass p-6 pr-20 rounded-3xl text-sm text-white placeholder:text-slate-600 resize-none h-20 shadow-2xl"
                disabled={loading}
              />
              <button 
                onClick={handleProcessQuery}
                disabled={loading || !query.trim()}
                className="absolute right-4 bottom-4 btn-primary-gradient p-3 rounded-2xl disabled:opacity-30 disabled:cursor-not-allowed group-hover:scale-105 transition-all"
              >
                {loading ? <TailSpin color="#060e20" height={20} width={20} /> : <Send className="w-5 h-5" />}
              </button>
           </div>
           <p className="text-[10px] text-center text-slate-600 mt-4 font-medium uppercase tracking-widest">
             Enterprise Intelligence Layer &bull; Premium v3.1
           </p>
        </div>
      </main>

      {/* 3. Right Panel: Context & Citations */}
      <aside className="w-80 glass-panel border-l border-white/5 flex flex-col shrink-0">
        <div className="p-6 border-b border-white/5">
           <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Contextual Sources</h3>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {response?.relevant_quotes && response.relevant_quotes.length > 0 ? (
            response.relevant_quotes.map((quote, idx) => (
              <div key={idx} className="glass-card p-4 rounded-2xl bg-white/5 border-l-2 border-cyan-500/50 animate-fade-in" style={{ animationDelay: `${idx * 0.1}s` }}>
                 <p className="text-[10px] text-cyan-400 font-bold mb-2 uppercase tracking-tighter">Verified Citation #{idx + 1}</p>
                 <p className="text-xs text-slate-400 italic leading-relaxed">"{quote}"</p>
              </div>
            ))
          ) : (
            <div className="h-full flex flex-col items-center justify-center opacity-20 grayscale">
               <FileText className="w-12 h-12 mb-4" />
               <p className="text-[10px] font-bold uppercase">No citations active</p>
            </div>
          )}
        </div>
        
        {/* History Quick-Access */}
        <div className="p-4 border-t border-white/5">
           <h3 className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-4 px-2">Recent Queries</h3>
           <div className="space-y-2 max-h-48 overflow-y-auto pr-2">
              {queryHistory.slice(0, 5).map((item) => (
                <button 
                  key={item.id} 
                  onClick={() => setQuery(item.query)}
                  className="w-full text-left p-3 rounded-xl hover:bg-white/5 border border-transparent hover:border-white/5 transition-all group"
                >
                  <p className="text-[11px] text-slate-400 truncate group-hover:text-cyan-300 font-medium">{item.query}</p>
                  <p className="text-[9px] text-slate-600 mt-1">{new Date(item.created_at).toLocaleDateString()}</p>
                </button>
              ))}
           </div>
        </div>
      </aside>
    </div>
  );
};

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/profile" element={
        <ProtectedRoute>
          <ProfilePage />
        </ProtectedRoute>
      } />
      <Route 
        path="/" 
        element={
          <ProtectedRoute>
            <MainApp />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

export default App;
