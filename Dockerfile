FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos "" appuser
RUN chown -R appuser:appuser /app
USER appuser

# Run the application
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
