FROM python:3.12.15-alpine3.24@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements-hosted.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-hosted.lock \
    && python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && addgroup -S -g 10001 cleartrail \
    && adduser -S -D -H -u 10001 -G cleartrail cleartrail
COPY cleartrail/ ./cleartrail/
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "cleartrail.hosted:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers", "--no-access-log", "--limit-concurrency", "64", "--timeout-keep-alive", "5"]
