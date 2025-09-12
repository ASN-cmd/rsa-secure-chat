# Use Python 3.9 with additional build tools
FROM python:3.9-slim as builder

# Install system dependencies (for SQLite, crypto, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# --- Runtime stage ---
FROM python:3.9-slim
WORKDIR /app

# Copy virtual env from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy app files
COPY server/ .

# Environment variables
ENV FLASK_APP=server.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# WebSocket/HTTP port
EXPOSE 8765

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:$PORT/health || exit 1

# Start both HTTP and WebSocket servers
CMD ["sh", "-c", \
     "gunicorn --bind 0.0.0.0:$PORT --workers 1 server:app & \
     python -c \"import asyncio; from server import ChatServer; \
     asyncio.run(ChatServer(host='0.0.0.0').start_websocket_server()\""]