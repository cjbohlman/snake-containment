FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all necessary files for installation
COPY pyproject.toml ./
COPY README.md ./
COPY src/ ./src/
COPY entrypoint.sh ./

# Install the package
RUN pip install -e .

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]