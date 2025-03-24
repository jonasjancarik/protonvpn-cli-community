FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openvpn \
    dialog \
    iptables \
    iputils-ping \
    net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Install the application
RUN pip install -e .

# The application needs to run as root
USER root

# Make the entrypoint script executable
COPY vpn-entrypoint.sh /vpn-entrypoint.sh
RUN chmod +x /vpn-entrypoint.sh

# Set the entrypoint to our script
ENTRYPOINT ["/vpn-entrypoint.sh"]

# Expose the API port
EXPOSE 8000 