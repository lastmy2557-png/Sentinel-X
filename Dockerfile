# ==============================================================================
# Sentinel-X — Hardened Container Image for GitHub Packages (ghcr.io)
# Runs as a non-root user with zero external runtime dependencies.
# ==============================================================================
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Sentinel-X" \
      org.opencontainers.image.description="Sentinel-X Cybersecurity, SOC, Threat Detection & Release Protection Platform" \
      org.opencontainers.image.source="https://github.com/lastmy2557-png/Sentinel-X" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_ENV=production \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=8080 \
    SENTINEL_DB_PATH=/app/data/runtime/sentinel_x.db \
    SENTINEL_AUDIT_LOG_PATH=/app/logs/audit.log

# Create non-root group and user
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -m -s /usr/sbin/nologin sentinel

WORKDIR /app

COPY sentinel_x/ /app/sentinel_x/
COPY config/ /app/config/
COPY data/samples/ /app/data/samples/
COPY pyproject.toml README.md .gitignore /app/

RUN mkdir -p /app/data/runtime /app/logs && \
    chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8080

ENTRYPOINT ["python3", "-m", "sentinel_x"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
