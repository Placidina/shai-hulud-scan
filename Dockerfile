FROM alpine:3.22.2

RUN set -eux \
    && apk add --no-cache \
    python3 \
    py3-pip

WORKDIR /scan
COPY . /opt/shai-hulud-scan

RUN set -eux \
    && pip install --break-system-packages -r /opt/shai-hulud-scan/requirements.txt

RUN cat > "/usr/bin/shai-hulud-scan" << 'EOF'
#!/bin/sh
cd /opt/shai-hulud-scan
exec python3 shai-hulud-scan.py "$@"
EOF

RUN set -eux \
    && chmod +x /usr/bin/shai-hulud-scan

CMD ["shai-hulud-scan", "/scan", "--fail"]
