# WebVulnScan

A Python web application for scanning web vulnerabilities.  

---

## Requirements

- [Docker](https://www.docker.com/get-started) installed on your system

---

## Quick Start

```bash
# 1. Build the Docker image
docker build -t webvulnscan .

# 2. Run the container
docker run --rm -p 5000:5000 webvulnscan
# 3. Access the application
# Open your browser and navigate to: http://localhost:5000