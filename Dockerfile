# Use lightweight Python image
FROM python:3.12-slim

# Prevent Python cache files and enable logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Copy requirements first
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy ShieldAI source code
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Start ShieldAI API server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
