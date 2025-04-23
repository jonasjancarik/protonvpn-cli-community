FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Python and system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    openvpn \
    dialog \
    iptables \
    iputils-ping \
    net-tools \
    iproute2 \
    procps \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip3 install --upgrade pip
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Install the application
RUN pip3 install -e .

# The application needs to run as root
USER root

# Make the entrypoint script executable
COPY vpn-entrypoint.sh /vpn-entrypoint.sh
RUN chmod +x /vpn-entrypoint.sh

# Set the entrypoint to our script
# ENTRYPOINT ["/vpn-entrypoint.sh"]

# open the shell
# CMD ["tail", "-f", "/dev/null"]

# Expose the API port
EXPOSE 8000 