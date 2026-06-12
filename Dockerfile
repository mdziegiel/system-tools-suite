FROM node:lts-alpine AS frontend-build
WORKDIR /app
ENV NPM_CONFIG_LOGLEVEL=warn CI=true
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm i --frozen-lockfile
COPY . .
RUN pnpm build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    DIST_DIR=/app/dist
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping traceroute dnsutils whois openssl smartmontools file libimage-exiftool-perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend /app/backend
COPY --from=frontend-build /app/dist /app/dist
VOLUME ["/data"]
EXPOSE 10233
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "10233"]
