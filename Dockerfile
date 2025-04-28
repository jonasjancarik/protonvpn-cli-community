# Using 22.04 - ran into an issue with installing system-wide on 24.04 
FROM ubuntu:22.04
# Install uv without /uvx (we don't need it)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Python and other system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    # python3-pip \
    openvpn \
    dialog \
    iptables \
    iputils-ping \
    net-tools \
    iproute2 \
    procps \
    git \
    tini \
    gnupg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the application code including pyproject.toml
COPY . .

# The application needs to run as root
USER root

# Install the application using uv
# uv automatically uses pyproject.toml
RUN uv pip install -e . --system

# Make the entrypoint script executable
COPY vpn-entrypoint.sh /vpn-entrypoint.sh
RUN chmod +x /vpn-entrypoint.sh

# ENTRYPOINT [\"/usr/bin/tini\", \"--\"]   # PID 1 = tini, always, can reap zombie processes
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD "/vpn-entrypoint.sh"           # what happens in "normal" runs

# open the shell
# CMD ["tail", "-f", "/dev/null"]

# Expose the API port
EXPOSE 8000 