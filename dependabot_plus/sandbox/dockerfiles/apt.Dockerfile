FROM debian:bookworm

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        inotify-tools python3 procps && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /sandbox

ENTRYPOINT ["/entrypoint.sh"]
