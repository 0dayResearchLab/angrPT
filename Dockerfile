FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-virtualenv \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory for angrPT
WORKDIR /app

# Clone the angrPT repository
RUN git clone https://github.com/0dayResearchLab/angrPT.git .

# Set up a Python virtual environment
RUN virtualenv -p python3 venv

# Activate the virtual environment and install Python dependencies
RUN . venv/bin/activate && \
    pip install --no-cache-dir \
    angr \
    virtualenvwrapper \
    boltons \
    argparse \
    ipdb \
    r2pipe \
    angr-utils

# Clone and install angr-dev dependencies (bingraphvis and angr-utils)
RUN . venv/bin/activate && \
    git clone https://github.com/axt/bingraphvis.git && \
    cd bingraphvis && \
    pip install -e . && \
    cd .. && \
    git clone https://github.com/axt/angr-utils.git && \
    cd angr-utils && \
    pip install -e .

# Set the entrypoint to run angrPT with Python in the virtual environment
ENTRYPOINT ["/app/venv/bin/python", "/app/angrpt.py"]
