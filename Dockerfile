FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/app/instance \
    ZAP_JAR=/opt/zap/ZAP_2.17.0/zap-2.17.0.jar

RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jre-headless curl unzip ca-certificates tini gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/zap \
    && curl -fL --retry 3 https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip -o /tmp/zap.zip \
    && echo '94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0  /tmp/zap.zip' | sha256sum -c - \
    && unzip -q /tmp/zap.zip -d /opt/zap \
    && rm /tmp/zap.zip

WORKDIR /app
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt \
    && groupadd --gid 10001 vulntrack \
    && useradd --uid 10001 --gid 10001 --no-create-home vulntrack \
    && mkdir -p /app/instance \
    && chown 10001:10001 /app/instance

COPY app.py ./
COPY vulntrack ./vulntrack
COPY deploy/railway_start.py ./deploy/railway_start.py
USER 10001:10001
EXPOSE 5000
CMD ["tini", "--", "python", "deploy/railway_start.py"]
