FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

LABEL org.opencontainers.image.source="https://github.com/web3wes/agentcomms"
LABEL org.opencontainers.image.description="Experimental agent-to-agent messaging MCP server"

WORKDIR /app

COPY requirements-runtime.lock ./
RUN python -m pip install --no-cache-dir --only-binary=:all: \
        --require-hashes -r requirements-runtime.lock && \
    python -m pip uninstall --yes pip setuptools && \
    mkdir -p /data

COPY agentcomms.py agentcomms_v2.py agentcomms_mcp.py ./

ENV AGENTCOMMS_HOME=/data \
    AGENTCOMMS_HUB=https://web3wes.pythonanywhere.com \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]

CMD ["python", "agentcomms_mcp.py"]
