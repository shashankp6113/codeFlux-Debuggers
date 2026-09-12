FROM python:3.12-slim

# Create a non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -m appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure the non-root user has ownership of the app directory (needed if writing sqlite/logs locally)
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Run uvicorn
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000"]
