FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create database and add test user
RUN sqlite3 users.db "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);" && \
    sqlite3 users.db "INSERT INTO users (username, password) VALUES ('admin', '5f4dcc3b5aa765d61d8327deb882cf99');"

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
