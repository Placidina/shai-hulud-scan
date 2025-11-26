FROM node:22

RUN set -eux \
    && apt-get update \
    && apt-get install -y \
    git \
    python3 \
    python3-pip \
    && apt-get clean

WORKDIR /workspace
COPY . /opt/shai-hulud-scan

RUN set -eux \
    && pip install --break-system-packages -r /opt/shai-hulud-scan/requirements.txt

RUN cat > "/usr/bin/shai-hulud-scan" << 'EOF'
#!/bin/sh
cd /opt/shai-hulud-scan
exec python3 shai-hulud-scan.py "$@"
EOF

RUN chmod +x /usr/bin/shai-hulud-scan

CMD ["tail", "-f", "/dev/null"]
