# Rafter CLI — Docker image for CI pipelines
#
# Build:
#   docker build -t rafter/cli .
#
# Usage:
#   docker run --rm -v "$(pwd):/workspace" rafter/cli secrets /workspace
#   docker run --rm -v "$(pwd):/workspace" rafter/cli secrets /workspace --format json
#
# In CI (e.g. GitLab CI, Jenkins):
#   image: rafter/cli
#   script: rafter secrets . --quiet
#
# Exit codes: 0 = clean, 1 = secrets found, 2 = scanner error

FROM node:22-alpine

RUN apk add --no-cache git \
    && npm install -g @rafter-security/cli \
    && rafter agent init --with-betterleaks

WORKDIR /workspace

ENTRYPOINT ["rafter"]
CMD ["--help"]
