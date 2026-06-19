# Use lightweight Python image
FROM python:3.12-slim


# Prevent Python cache files
ENV PYTHONDONTWRITEBYTECODE=1

# Enable real-time logs
ENV PYTHONUNBUFFERED=1


# Set working directory
WORKDIR /app


# Copy dependency file
COPY requirements.txt .


# Install dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# Copy application code
COPY . .


# API Port
EXPOSE 8000


# Start ShieldAI API
CMD [
    "uvicorn",
    "main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000"
]
