FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --chown=101:101 *.html /usr/share/nginx/html/
COPY --chown=101:101 static /usr/share/nginx/html/static
COPY --chown=101:101 ai-agent /usr/share/nginx/html/ai-agent

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8080/health >/dev/null || exit 1
