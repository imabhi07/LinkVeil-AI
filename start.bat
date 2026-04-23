@echo off
echo ===================================================
echo Starting LinkVeil-AI (PhishGuard) Development Server
echo ===================================================

:: Start the FastAPI backend in a new window
echo Starting Backend (FastAPI)...
start "LinkVeil Backend" cmd /k "uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000"

:: Start the React frontend in a new window
echo Starting Frontend (React/Vite)...
start "LinkVeil Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo Both servers are starting up!
echo Backend will be available at: http://localhost:8000/docs
echo Frontend will be available at: http://localhost:5173
echo.
pause
