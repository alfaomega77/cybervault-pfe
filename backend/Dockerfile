FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AISS_POLICY_PATH=/app/config/default_policy.yaml \
    AISS_WEB_ROOT=/app/web

WORKDIR /app

ARG INSTALL_DEEP_LEARNING=false
COPY requirements.txt requirements-deep-learning.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_DEEP_LEARNING" = "true" ]; then \
         pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \
           -r requirements-deep-learning.txt; \
       fi \
    && groupadd --gid 10001 cybervault \
    && useradd --uid 10001 --gid cybervault --home-dir /app --shell /usr/sbin/nologin cybervault

COPY --chown=cybervault:cybervault aiss ./aiss
COPY --chown=cybervault:cybervault config ./config
COPY --chown=cybervault:cybervault schemas ./schemas
RUN mkdir -p /app/data /app/web \
    && chown cybervault:cybervault /app/data /app/web

USER cybervault
EXPOSE 8090

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=3)"
CMD ["python", "-m", "aiss.consumer.main"]
