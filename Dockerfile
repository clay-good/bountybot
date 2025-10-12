# bountybot Dockerfile
# Production-ready container for AI-powered bug bounty validation

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install bountybot in development mode
RUN pip install --no-cache-dir -e .

# Create output directory
RUN mkdir -p /app/validation_results

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Run as non-root user for security
RUN useradd -m -u 1000 bountybot && \
    chown -R bountybot:bountybot /app
USER bountybot

# Default command shows help
CMD ["python3", "-m", "bountybot.cli", "--help"]

