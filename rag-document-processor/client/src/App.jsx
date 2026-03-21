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
    setResponse(null);

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
      // For now, just show the content in an alert. In a real app, you'd show this in a modal
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

  // Removed medical decision helpers.

  return (
    <div className="min-h-screen bg-slate-950 font-sans text-slate-200">
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
         <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/10 blur-[120px] rounded-full"></div>
      </div>
      <div className="relative z-10 max-w-7xl mx-auto p-4 md:p-8 pt-6">
        {/* Header */}
        <header className="flex flex-col md:flex-row justify-between items-center gap-6 mb-8 border-b border-white/5 pb-6">
            <div className="flex items-center gap-3">
                <div className="bg-indigo-500/10 p-2.5 rounded-xl border border-indigo-500/20">
                    <FileText className="w-8 h-8 text-indigo-400" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold text-white tracking-tight">Document Analyst</h1>
                  <p className="text-sm text-slate-400 mt-1">Universal RAG Workspace</p>
                </div>
            </div>
            <div className="flex items-center gap-4">
                <Link to="/profile" className="text-indigo-300 hover:text-indigo-200 transition-colors flex items-center gap-2 text-sm font-medium bg-indigo-500/10 px-4 py-2 rounded-xl border border-indigo-500/20 shadow-[0_0_15px_rgba(79,70,229,0.1)]">
                    <User className="w-4 h-4"/> <span className="hidden sm:inline">{user?.username || 'Profile'}</span>
                </Link>
                <button onClick={logout} className="text-slate-400 hover:text-red-400 transition-colors flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-xl hover:bg-slate-900/50 border border-transparent hover:border-red-500/20">
                    <LogOut className="w-4 h-4" />
                    <span className="hidden sm:inline">Sign Out</span>
                </button>
            </div>
        </header>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Left Panel - Input */}
          <div className="glass-panel bg-slate-900/40 p-6 rounded-2xl border border-white/5 backdrop-blur-xl">
            <h2 className="text-lg font-semibold text-white mb-6">
              Document Management & Query
            </h2>
            
            {/* Document Upload Section */}
            <div className="mb-6 p-5 bg-slate-800/30 rounded-xl border border-white/5">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2"><Upload className="w-4 h-4"/> Upload Documents</h3>
              
              <div className="space-y-3">
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  accept=".pdf,.txt,.docx,.eml"
                  onChange={handleFileUpload}
                  className="hidden"
                />
                
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={uploading}
                  className="w-full bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/30 text-indigo-300 disabled:opacity-50 font-medium py-4 px-6 rounded-xl transition-all duration-200 flex items-center justify-center gap-3"
                >
                  {uploading ? (
                    <>
                      <TailSpin color="white" height={20} width={20} />
                      Uploading... {uploadProgress}%
                    </>
                  ) : (
                    <>
                      <Upload className="w-5 h-5" />
                      Choose PDF/Document Files
                    </>
                  )}
                </button>
                
                {uploadProgress > 0 && uploading && (
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-blue-600 h-2 rounded-full transition-all duration-300" 
                      style={{ width: `${uploadProgress}%` }}
                    ></div>
                  </div>
                )}
              </div>
            </div>

            {/* Documents List */}
            {documents.length > 0 && (
              <div className="mb-6 p-5 bg-slate-800/30 rounded-xl border border-white/5">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4">Uploaded Documents ({documents.length})</h3>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {documents.map((doc) => (
                    <div key={doc.id} className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg border border-white/5">
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-slate-200 truncate">{doc.name}</p>
                        <p className="text-xs text-slate-500">
                          {doc.type} • {(doc.size / 1024).toFixed(1)} KB
                        </p>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => viewDocument(doc.id)}
                          className="p-1.5 text-indigo-400 hover:bg-indigo-500/20 rounded-md transition-colors"
                          title="View content"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => deleteDocument(doc.id)}
                          className="p-1.5 text-red-400 hover:bg-red-500/20 rounded-md transition-colors"
                          title="Delete document"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            <div className="space-y-4">
              <div className="pt-2">
                <label htmlFor="query" className="block text-slate-400 text-xs font-medium mb-2 uppercase tracking-wider">
                  Ask a question about your documents:
                </label>
                <textarea
                  id="query"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="e.g., What are the key points mentioned in the first chapter?"
                  className="w-full h-32 px-4 py-3 bg-slate-800/50 border border-white/5 rounded-xl text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 transition-colors placeholder:text-slate-600 resize-none"
                  disabled={loading}
                />
              </div>

              <button
                onClick={handleProcessQuery}
                disabled={loading || !query.trim()}
                className="w-full bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed text-white shadow-[0_0_15px_rgba(79,70,229,0.3)] font-medium py-3.5 px-6 rounded-xl transition-all duration-200 flex items-center justify-center gap-2 text-sm"
              >
                {loading ? (
                  <>
                    <TailSpin color="white" height={20} width={20} />
                    Processing...
                  </>
                ) : (
                  <>
                    <Send className="w-5 h-5" />
                    Process Query
                  </>
                )}
              </button>
            </div>

            {/* Query History */}
            <div className="mt-6 pt-6 border-t border-white/5">
              <h3 className="text-slate-400 text-xs font-medium mb-3 uppercase tracking-wider">Query History:</h3>
              <div className="border border-white/5 rounded-xl max-h-48 overflow-y-auto bg-slate-900/20">
                {queryHistory.length > 0 ? (
                  queryHistory.map((item, index) => (
                    <HistoryItem
                      key={item.id} // Use the database ID as the key
                      item={item}
                      onQuerySelect={setQuery}
                      onDelete={() => handleDeleteHistoryItem(item.id)}
                    />
                  ))
                ) : (
                  <p className="p-4 text-slate-500 text-sm">No query history found.</p>
                )}
              </div>
            </div>
          </div>

          {/* Right Panel - Results */}
          <div className="glass-panel bg-slate-900/40 p-6 rounded-2xl border border-white/5 backdrop-blur-xl shrink-0 h-fit">
            <h2 className="text-lg font-semibold text-white mb-6">
              AI Analysis Results
            </h2>

            {loading && (
              <div className="flex flex-col items-center justify-center py-12">
                <TailSpin color="#818cf8" height={60} width={60} />
                <p className="mt-4 text-slate-400">Analyzing your query against policy documents...</p>
              </div>
            )}

            {error && (
              <div className="bg-red-900/20 border border-red-500/20 rounded-xl p-4">
                <div className="flex items-center gap-2">
                  <XCircle className="w-5 h-5 text-red-400" />
                  <span className="text-red-300 font-medium">Error</span>
                </div>
                <p className="text-red-400/80 mt-2 text-sm">{error}</p>
              </div>
            )}

            {response && !loading && (
              <div className="border rounded-xl p-6 bg-slate-800/30 border-white/5 shadow-sm">
                
                {/* Answer section */}
                <div className="mb-6">
                  <h4 className="text-xs font-semibold text-indigo-400 mb-3 uppercase tracking-wider">Answer</h4>
                  <p className="text-slate-200 leading-relaxed text-lg whitespace-pre-wrap">
                    {response.answer}
                  </p>
                </div>

                {/* Relevant Quotes */}
                {response.relevant_quotes && response.relevant_quotes.length > 0 && (
                  <div className="mb-4">
                    <h4 className="text-xs font-semibold text-slate-400 mb-3 uppercase tracking-wider">Relevant Quotes</h4>
                    <ul className="list-disc pl-5 space-y-2">
                      {response.relevant_quotes.map((quote, idx) => (
                        <li key={idx} className="text-slate-400 italic text-sm border-l-2 border-indigo-500/30 pl-3">"{quote}"</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Confidence */}
                <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-between">
                  <span className="text-xs text-slate-500 font-medium uppercase tracking-wider">Confidence Level:</span>
                  <span className={`text-xs px-2.5 py-1 rounded-full font-semibold ${
                    response.confidence === 'high' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                    response.confidence === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                    'bg-red-500/10 text-red-400 border border-red-500/20'
                  }`}>
                    {response.confidence ? response.confidence.toUpperCase() : 'UNKNOWN'}
                  </span>
                </div>
                
                {/* Raw Response */}
                <details className="mt-6">
                  <summary className="text-sm font-medium text-slate-500 cursor-pointer hover:text-slate-300 transition-colors">
                    View Raw AI Response
                  </summary>
                  <pre className="mt-3 p-4 bg-slate-900/60 border border-white/5 rounded-xl text-xs text-slate-400 overflow-x-auto">
                    {JSON.stringify(response, null, 2)}
                  </pre>
                </details>
              </div>
            )}

            {!loading && !error && !response && (
              <div className="text-center py-12 text-slate-500">
                <FileText className="w-16 h-16 mx-auto mb-4 text-slate-700" />
                <p className="text-lg text-slate-300 font-medium">Submit a query</p>
                <p className="text-sm mt-2 max-w-sm mx-auto">The system will analyze your query against your documents and provide a comprehensive answer</p>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-12 text-slate-600 text-sm pb-8">
          <p>Powered by Gemini API, LangChain, and ChromaDB/Pinecone</p>
          <p className="mt-1">Universal Document RAG Analyst</p>
        </div>
      </div>
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
