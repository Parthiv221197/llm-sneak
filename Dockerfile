FROM python:3.12-slim

LABEL org.opencontainers.image.title="llm-sneak" \
      org.opencontainers.image.description="LLM Security Scanner — Like Nmap, but for AI" \
      org.opencontainers.image.url="https://github.com/safellm/llm-sneak" \
      org.opencontainers.image.licenses="MIT"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml setup.py setup.cfg ./
COPY llmsneak/ ./llmsneak/

# Install
RUN pip install --no-cache-dir . && \
    # Smoke test
    llm-sneak --version

# Run as non-root
RUN useradd -m -u 1000 scanner
USER scanner

# llm-sneak is now the default command
# Usage:
#   docker run --rm llm-sneak http://host.docker.internal:11434
#   docker run --rm llm-sneak -sV --api-key $KEY https://api.openai.com
ENTRYPOINT ["llm-sneak"]
CMD ["--help"]
