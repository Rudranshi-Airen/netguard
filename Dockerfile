# NetGuard: C11 compiler core + Flask web layer, for Render (or any Docker host).
#
# Stage 1 compiles bin/netguard for Linux inside the image (the macOS binary in a
# developer checkout is never used). Stage 2 is the runtime: Python + gunicorn,
# the compiled binary, the web app and the examples (incl. examples/ai_cache).

FROM python:3.11-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev make \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY core ./core
RUN make && ./bin/netguard compile /dev/null --syntax fw --json > /dev/null

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000
WORKDIR /app
COPY web/requirements.txt web/requirements.txt
RUN pip install --no-cache-dir -r web/requirements.txt
COPY web ./web
COPY examples ./examples
COPY --from=build /src/bin/netguard ./bin/netguard
RUN useradd --create-home --uid 10001 netguard
USER netguard
EXPOSE 10000
# AI merge can take up to ~150 s (GEMINI_BUDGET), hence the long worker timeout.
CMD ["sh", "-c", "exec gunicorn --chdir web --bind 0.0.0.0:${PORT:-10000} --timeout 200 --workers 2 app:app"]
