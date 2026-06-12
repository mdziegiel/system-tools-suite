FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY index.html vite.config.ts tsconfig.json ./
COPY frontend ./frontend
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    DIST_DIR=/app/dist
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping traceroute dnsutils whois openssl smartmontools file libimage-exiftool-perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend /app/backend
COPY --from=frontend-build /app/dist /app/dist
VOLUME ["/data"]
EXPOSE 10233
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:10233/api/health', timeout=5).read()"
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "10233"]
