FROM golang:1.27.1-bookworm AS go-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        git \
        ca-certificates \
        curl \
        unzip && \
    rm -rf /var/lib/apt/lists/*

ENV GO111MODULE=on

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/alterx/cmd/alterx@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# TruffleHog: official release installer
RUN curl -sSfL \
    https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /go/bin

# Findomain: official precompiled Linux release
RUN curl -fL \
    https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    -o /tmp/findomain.zip && \
    unzip -q /tmp/findomain.zip -d /tmp/findomain && \
    install -m 0755 /tmp/findomain/findomain /go/bin/findomain && \
    rm -rf /tmp/findomain /tmp/findomain.zip


FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH=/usr/local/bin:$PATH

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        curl \
        libgcc-s1 && \
    rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir wafw00f

COPY --from=go-builder /go/bin/ /usr/local/bin/

RUN git clone --depth 1 \
    https://github.com/danielmiessler/SecLists.git \
    /opt/seclists

COPY backend ./backend
COPY frontend ./frontend

WORKDIR /app

CMD ["python", "-m", "backend.worker"]