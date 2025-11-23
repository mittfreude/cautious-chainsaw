#!/bin/bash

# SigmaForge Next.js Startup Script
# This script starts both the FastAPI backend and Next.js frontend

echo "🛡️  Starting SigmaForge Next.js version..."
echo ""

# Check if OPENAI_API_KEY is set
if [ -z "$OPENAI_API_KEY" ]; then
    echo "⚠️  Warning: OPENAI_API_KEY environment variable is not set"
    echo "Please set it before continuing:"
    echo "export OPENAI_API_KEY='your-api-key-here'"
    echo ""
    read -p "Press Enter to continue anyway or Ctrl+C to exit..."
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down SigmaForge..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup INT TERM

# Start the backend
echo "🚀 Starting FastAPI backend on port 8000..."
cd backend
python main.py &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 3

# Start the frontend
echo "🎨 Starting Next.js frontend on port 3000..."
cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    npm install
fi

npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ SigmaForge is running!"
echo ""
echo "Backend API:  http://localhost:8000"
echo "Frontend UI:  http://localhost:3000"
echo "API Docs:     http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop both services"
echo ""

# Wait for processes
wait
