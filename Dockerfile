# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create a startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "🔧 Configuring RAXE..."\n\
\n\
# Export RAXE_API_KEY as environment variable (RAXE Python SDK uses it directly)\n\
if [ -n "$RAXE_API_KEY" ]; then\n\
    echo "✅ RAXE_API_KEY is set"\n\
    export RAXE_API_KEY\n\
else\n\
    echo "⚠️  Warning: RAXE_API_KEY not set in environment"\n\
fi\n\
\n\
echo "🏥 Running RAXE health check..."\n\
python3 -c "from raxe import Raxe; print(\"✅ RAXE initialized successfully\")" || echo "⚠️  RAXE initialization check completed with warnings"\n\
\n\
echo "🚀 Starting FastAPI server..."\n\
exec uvicorn app.main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"\n\
' > /app/start.sh && chmod +x /app/start.sh

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run startup script
CMD ["/app/start.sh"]

