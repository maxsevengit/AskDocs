# Med-RAG: Medical Document RAG System

A full-stack Retrieval-Augmented Generation (RAG) system for analyzing uploaded documents with AI-powered answers and citations.

## 🚀 Features

- **AI-Powered Claims Processing**: Uses Gemini API to analyze claims against policy documents
- **Document Retrieval**: PostgreSQL + pgvector for efficient document similarity search
- **Structured Responses**: Returns JSON responses with answer, relevant quotes, and confidence
- **Modern UI**: Clean, responsive React frontend with Tailwind CSS
- **Real-time Processing**: Instant analysis of medical claims queries

## 🏗️ Architecture

```
Frontend (React + Vite + Firebase Auth) → Backend (Node.js + Express) → pgvector → Gemini API
```

## 📁 Project Structure

```
rag-document-processor/
├── client/                 # React frontend
│   ├── src/
│   │   ├── App.jsx        # Main React component
│   │   ├── main.jsx       # React entry point
│   │   └── index.css      # Tailwind CSS styles
│   ├── package.json       # Frontend dependencies
│   └── vite.config.js     # Vite configuration
├── server/                 # Node.js backend
│   ├── index.js           # Express server + RAG pipeline
│   ├── database.js        # PostgreSQL + pgvector initialization
│   ├── uploads/           # Uploaded files
│   ├── package.json       # Backend dependencies
│   └── .env               # Environment variables
└── README.md              # This file
```

## 🛠️ Technology Stack

### Frontend
- **React 18** - Modern React with hooks
- **Vite** - Fast build tool and dev server
- **Tailwind CSS** - Utility-first CSS framework
- **Axios** - HTTP client for API calls
- **Lucide React** - Beautiful icons
- **React Loader Spinner** - Loading animations

### Backend
- **Node.js** - JavaScript runtime
- **Express** - Web framework
- **LangChain.js** - Text splitting utilities
- **PostgreSQL + pgvector** - Vector storage and similarity search
- **Xenova Transformers** - Local embeddings (fallback available)
- **Axios** - HTTP client for Gemini API calls

### AI Services
- **Gemini API** - Google's latest LLM for claims analysis
- **Firebase Auth** - Email/password + Google OAuth

## 📋 Prerequisites

- Node.js 18+ and npm
- Gemini API key from Google AI Studio
- PostgreSQL with pgvector (or Docker Compose)
- Firebase project (for client auth)

## 🚀 Setup Instructions

### 1. Clone and Navigate
```bash
cd rag-document-processor
```

### 2. Backend Setup
```bash
cd server

# Install dependencies
npm install

# Set up environment variables
# Edit .env file and add your Gemini API key:
# GEMINI_API_KEY="your_actual_api_key_here"

# Optional: JWT_SECRET and mailer settings
# JWT_SECRET="your_jwt_secret_here"
# MAIL_USER="your_mail_user"
# MAIL_PASS="your_mail_pass"
# MAIL_FROM="your_mail_from"
```

### 3. Frontend Setup
```bash
cd ../client

# Install dependencies
npm install
```

Create a `client/.env` file for Firebase:
```
VITE_FIREBASE_API_KEY="..."
VITE_FIREBASE_AUTH_DOMAIN="..."
VITE_FIREBASE_PROJECT_ID="..."
VITE_FIREBASE_STORAGE_BUCKET="..."
VITE_FIREBASE_MESSAGING_SENDER_ID="..."
VITE_FIREBASE_APP_ID="..."
VITE_FIREBASE_MEASUREMENT_ID="..."
```

### 4. Start the Application

#### Terminal 1 - Backend
```bash
cd server
npm start
```
The server will start on port 3001 and initialize the RAG pipeline.

#### Terminal 2 - Frontend
```bash
cd client
npm run dev
```
The frontend will start on port 5173.

### 5. Docker (Optional)
```bash
docker-compose up --build
```
This will start Postgres + backend + frontend. Frontend will be available at `http://localhost:5173`.

### 5. Access the Application
Open your browser and navigate to: `http://localhost:5173`

## 🔑 API Configuration

### Gemini API Setup
1. Visit [Google AI Studio](https://aistudio.google.com/)
2. Create a new API key
3. Add it to `server/.env`:
   ```
   GEMINI_API_KEY="your_api_key_here"
   ```

### Firebase Auth Setup
1. Create a Firebase project and enable Email/Password + Google providers
2. Add the Firebase web config to `client/.env`

## 📖 Usage

### 1. Submit a Query
- Type your medical claim question in the left panel
- Use the example queries for inspiration
- Click "Process Query" or press Enter

### 2. View Results
- The right panel displays AI analysis results
- Read the answer and relevant quotes
- Expand "View Raw AI Response" for technical details

### 3. Example Queries
- **Age-based coverage**: "I'm 25 years old and need hip surgery. I live in Delhi. What's covered?"
- **Policy timing**: "My 3-month-old child needs medical treatment. Is this covered?"
- **Location-based payouts**: "I need surgery in a small town. What's the maximum payout?"
- **Age restrictions**: "I'm 65 years old. Are my medical procedures covered?"

## 🔍 How It Works

1. **Document Upload**: Users upload documents via the UI
2. **Text Processing**: Documents are split into chunks using a text splitter
3. **Embedding Generation**: Text chunks are converted to vector embeddings
4. **Vector Storage**: Embeddings are stored in pgvector for similarity search
5. **Query Processing**: User queries are embedded and compared
6. **Document Retrieval**: Top relevant chunks are retrieved
7. **AI Analysis**: Gemini API analyzes the query against retrieved context
8. **Response Generation**: Structured JSON response with answer and confidence

## 📄 Documents

Upload your own policy or reference documents through the UI. The system indexes only the documents you upload.

## 🧪 Testing

### Test Queries
1. **Approved Claim**: "I'm 30 years old, need knee surgery, live in Mumbai, and my policy is 1 year old"
2. **Rejected Claim**: "I'm 17 years old and need medical treatment"
3. **Rejected Claim**: "I need hip surgery but my policy is only 3 months old"

### Health Check
Test the backend health: `GET http://localhost:3001/health`

## 🐛 Troubleshooting

### Common Issues

1. **"RAG pipeline not yet initialized"**
   - Wait for server startup to complete
   - Check server console for initialization errors

2. **"Unable to connect to server"**
   - Ensure backend is running on port 3001
   - Ensure PostgreSQL with pgvector is running

3. **"Invalid request to Gemini API"**
   - Verify your API key in `.env`
   - Check API key permissions and quotas

4. **Embedding errors**
   - Consider adding a HuggingFace API key
   - Check internet connectivity for model downloads

### Debug Mode
Enable detailed logging by checking the server console output.

## 🔧 Development

### Adding New Documents
1. Upload documents via the UI
2. Documents are automatically indexed

### Modifying the RAG Pipeline
- Edit `server/index.js` to change chunk sizes, similarity search parameters
- Modify the Gemini prompt in the `/process-query` endpoint

### Customizing the Frontend
- Edit `client/src/App.jsx` for UI changes
- Modify `client/src/index.css` for styling updates

## 📈 Performance

- **Query Processing**: ~3-5 seconds (depends on Gemini API response time)
- **Vector Search**: Sub-second similarity search

## 🔒 Security Notes

- API keys are stored in `.env` files (never commit these)
- CORS is configured for local development only
- Firebase auth is required to access protected API endpoints

## 🚀 Production Deployment

For production deployment:

1. **Environment Variables**: Use proper secret management
2. **Database**: Ensure pgvector is backed by persistent storage
3. **Authentication**: Add user authentication and authorization
4. **Rate Limiting**: Implement API rate limiting
5. **Monitoring**: Add logging and monitoring
6. **HTTPS**: Enable HTTPS for production

## 📝 License

MIT License - see LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For issues and questions:
- Check the troubleshooting section
- Review server console logs
- Ensure all dependencies are properly installed

---

**Built with ❤️ using React, Node.js, LangChain, and Gemini API**
