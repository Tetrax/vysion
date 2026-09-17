# syntax=docker/dockerfile:1
#
# Single image serving both the API and the UI.
#
# Layout inside the container:
#   /opt/vysion            application code + Références, owned by root, read-only to the app
#   /var/lib/vysion        working directory, writable by the app user
#   /var/lib/vysion/reports  generated reports (mount a volume here)
#
# Code and writable state are kept apart deliberately: the legacy report
# generators call wb.save(<relative filename>), so whatever directory the
# process runs from gets written to. Running from /var/lib/vysion means that is
# a data directory rather than the directory holding the source.

# ---------- stage 1: build the frontend ----------
FROM node:20-alpine AS frontend

WORKDIR /build
# package files first so npm ci is cached until dependencies actually change
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build


# ---------- stage 2: runtime ----------
FROM python:3.12-slim AS runtime

# C.UTF-8 matters here: the reference directory is named "Références" and the
# audit output is French. A non-UTF-8 filesystem encoding breaks both.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONPATH=/opt/vysion \
    REPORTS_DIR=/var/lib/vysion/reports \
    FRONTEND_DIR=/opt/vysion/static

WORKDIR /opt/vysion

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/Références ./Références
COPY --from=frontend /build/dist ./static

# Unprivileged user. The code stays root-owned so the running app cannot
# modify it; only the data directory is writable.
RUN useradd --system --uid 10001 --home-dir /var/lib/vysion --create-home vysion \
 && mkdir -p /var/lib/vysion/reports \
 && chown -R vysion:vysion /var/lib/vysion

USER vysion
WORKDIR /var/lib/vysion

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
