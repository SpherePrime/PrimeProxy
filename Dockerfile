# PrimeProxy — headless server image (CLI mode, no GUI/tray).
#
#   docker build -t primeproxy .
#   docker run -d -p 1443:1443 -p 1353:1353 primeproxy
#
# Config is stored in /root/.config/PrimeProxy. Mount a volume to keep it:
#   docker run -d -p 1443:1443 -v primeproxy-cfg:/root/.config primeproxy

FROM python:3.12-slim

WORKDIR /app

COPY . /app
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
ENV PRIMEPROXY_NO_TRAY=1

EXPOSE 1443/tcp 1353/tcp

ENTRYPOINT ["prime-proxy", "--cli"]
CMD ["server", "--tg"]