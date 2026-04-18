FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if any
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Assuming requirements.txt exists or will be generated
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || echo "Please create requirements.txt with fastapi, uvicorn, sqlalchemy, etc."

# We'll just install the basics if requirements fail
RUN pip install fastapi uvicorn sqlalchemy pydantic python-dotenv

# Copy the rest of the backend code
COPY . /app/backend

# Need to tell python where to find the 'backend.app' module
ENV PYTHONPATH=/app

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
