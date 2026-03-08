# Use official Python image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements first
COPY requirements.txt .
# Install system dependencies and Python requirements
RUN apt-get update \
	&& apt-get install -y --no-install-recommends nmap \
	&& rm -rf /var/lib/apt/lists/* \
	&& pip install --no-cache-dir -r requirements.txt

# Copy the rest of your project
COPY . .

# Run the app
CMD ["python", "-m", "app.app"]