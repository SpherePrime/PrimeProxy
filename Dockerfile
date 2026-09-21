# SwiftProxy — headless server image (CLI mode, no GUI/tray).
#
#   docker build -t swiftproxy .
#   docker run -d -p 1443:1443 -p 1353:1353 swiftproxy
#
# Config is stored in /root/.config/SwiftProxy. Mount a volume to keep it:
#   docker run -d -p 1443:1443 -v swiftproxy-cfg:/root/.config swiftproxy

FROM python:3.12-slim

WORKDIR /app

COPY . /app
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
ENV SWIFTPROXY_NO_TRAY=1

EXPOSE 1443/tcp 1353/tcp

ENTRYPOINT ["swift-proxy", "--cli"]
CMD ["server", "--tg"]