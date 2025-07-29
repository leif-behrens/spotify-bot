#!/bin/bash
# Start Script für Spotify Bot
# Startet sowohl den Hauptserver (Gunicorn) als auch den Callback-Server

set -e

echo "Starting Spotify Bot with dual server setup..."

# Function to handle shutdown
cleanup() {
    echo "Shutting down servers..."
    kill $CALLBACK_PID $MAIN_PID 2>/dev/null || true
    wait $CALLBACK_PID $MAIN_PID 2>/dev/null || true
    echo "Servers stopped."
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

echo "Starting Callback Server on port 4444..."
python /app/callback_server.py &
CALLBACK_PID=$!

echo "Callback Server PID: $CALLBACK_PID"

# Wait a moment for callback server to start
sleep 2

echo "Starting Main WSGI Server on port 8000..."
gunicorn --config gunicorn.conf.py wsgi:app &
MAIN_PID=$!

echo "Main Server PID: $MAIN_PID"

# Wait for both processes
wait $CALLBACK_PID $MAIN_PID