# SigmaForge Next.js Setup Guide

This guide explains how to run SigmaForge with the new Next.js frontend and FastAPI backend.

## 🏗️ Architecture

The application is now split into two parts:

1. **Frontend** (Next.js): Modern React-based UI
2. **Backend** (FastAPI): Python API exposing SigmaForge functionality

```
┌─────────────────┐         ┌─────────────────┐
│   Next.js       │  HTTP   │   FastAPI       │
│   Frontend      │◄───────►│   Backend       │
│  (Port 3000)    │  REST   │  (Port 8000)    │
└─────────────────┘         └─────────────────┘
                                    │
                                    ▼
                            ┌──────────────┐
                            │  SigmaForge  │
                            │  Core Logic  │
                            └──────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- OpenAI API key

### Step 1: Set Up the Backend

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Configure your OpenAI API key:
```bash
cd backend
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

3. Start the FastAPI backend:
```bash
cd backend
python main.py
```

The backend will start on http://localhost:8000

You can verify it's running by visiting http://localhost:8000/docs for the interactive API documentation.

### Step 2: Set Up the Frontend

1. Install Node.js dependencies:
```bash
cd frontend
npm install
```

2. Configure the API URL (optional):
```bash
cp .env.local.example .env.local
# Edit .env.local if your backend is not on localhost:8000
```

3. Start the Next.js development server:
```bash
npm run dev
```

The frontend will start on http://localhost:3000

### Step 3: Use the Application

Open http://localhost:3000 in your browser and start generating Sigma rules!

## 📋 Detailed Setup

### Backend Setup

The FastAPI backend exposes three main endpoints:

**1. Generate Rule** (`POST /api/generate`)
- Input: Threat description or example logs
- Output: Threat interpretation + Sigma rule

**2. Review Rule** (`POST /api/review`)
- Input: Existing Sigma rule
- Output: Improved Sigma rule

**3. Test Logs** (`POST /api/test-logs`)
- Input: Sigma rule + log lines
- Output: Match results for each log line

#### Backend Dependencies

```
fastapi>=0.104.0       # Web framework
uvicorn>=0.24.0        # ASGI server
pydantic>=2.0.0        # Data validation
openai>=1.3.0          # LLM client
pyyaml>=6.0.1          # YAML parsing
```

#### Running in Production

For production, use a production ASGI server:

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Frontend Setup

The Next.js frontend is a modern React application with:

- **TypeScript** for type safety
- **Tailwind CSS** for styling
- **Axios** for API calls
- **App Router** for routing

#### Frontend Dependencies

All dependencies are managed through npm. Key packages:

- `next` - Next.js framework
- `react` - React library
- `typescript` - TypeScript compiler
- `tailwindcss` - Utility-first CSS
- `axios` - HTTP client

#### Production Build

```bash
cd frontend
npm run build
npm start
```

For production deployment, consider:
- Vercel (recommended for Next.js)
- Docker container
- Node.js server with nginx reverse proxy

## 🔧 Configuration

### Environment Variables

**Backend** (`.env`):
```bash
OPENAI_API_KEY=your-api-key-here
```

**Frontend** (`.env.local`):
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### CORS Configuration

The backend is configured to accept requests from:
- `http://localhost:3000`
- `http://127.0.0.1:3000`

To add more origins, edit `backend/main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://your-domain.com"],
    ...
)
```

## 🐳 Docker Setup (Optional)

### Backend Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sigmaforge ./sigmaforge
COPY backend ./backend

WORKDIR /app/backend

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Frontend Dockerfile

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend .

RUN npm run build

CMD ["npm", "start"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile
    ports:
      - "8000:8000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}

  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:8000
    depends_on:
      - backend
```

## 🔍 Troubleshooting

### Backend won't start

**Error**: `ModuleNotFoundError: No module named 'sigmaforge'`

**Solution**: Make sure you're in the backend directory and the parent directory contains the sigmaforge package:
```bash
cd backend
python main.py
```

### Frontend can't connect to backend

**Error**: API requests fail with network errors

**Solutions**:
1. Check backend is running on port 8000
2. Verify `.env.local` has correct API URL
3. Check browser console for CORS errors
4. Ensure CORS origins include your frontend URL

### OpenAI API errors

**Error**: `AuthenticationError` or `RateLimitError`

**Solutions**:
1. Verify `OPENAI_API_KEY` is set correctly
2. Check your OpenAI account has credits
3. Ensure API key has proper permissions

## 📊 Performance Optimization

### Backend

- Use connection pooling for database (if added)
- Implement caching for frequent requests
- Use async database drivers
- Enable gzip compression

### Frontend

- Next.js automatically optimizes:
  - Code splitting
  - Image optimization
  - Font optimization
- Use `next/image` for images
- Implement React.memo for expensive components
- Use dynamic imports for code splitting

## 🔄 Migration from Streamlit

The original Streamlit app is still available in `app.py`. You can run both versions:

**Streamlit** (Port 8501):
```bash
streamlit run app.py
```

**Next.js** (Port 3000 + 8000):
```bash
# Terminal 1
cd backend && python main.py

# Terminal 2
cd frontend && npm run dev
```

## 📚 Additional Resources

- [Next.js Documentation](https://nextjs.org/docs)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Tailwind CSS](https://tailwindcss.com/docs)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)

## 🆘 Getting Help

If you encounter issues:

1. Check the API documentation at http://localhost:8000/docs
2. Review browser console for frontend errors
3. Check backend logs for Python errors
4. Ensure all environment variables are set
5. Verify all dependencies are installed

## 🎉 What's New in Next.js Version

✅ Modern React architecture
✅ TypeScript for type safety
✅ Faster page loads
✅ Better mobile experience
✅ Improved accessibility
✅ API-first design
✅ Easy to deploy
✅ Scalable architecture
