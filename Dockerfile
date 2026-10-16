FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/web3wes/agentcomms"
LABEL org.opencontainers.image.description="Experimental agent-to-agent messaging MCP server"

WORKDIR /app

COPY agentcomms.py agentcomms_mcp.py ./

ENV AGENTCOMMS_HOME=/data \
    AGENTCOMMS_HUB=https://web3wes.pythonanywhere.com \
    PYTHONUNBUFFERED=1

RUN mkdir -p /data

VOLUME ["/data"]

CMD ["python", "agentcomms_mcp.py"]
