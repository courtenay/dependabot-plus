FROM ruby:3.3-bookworm

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        inotify-tools python3 procps tcpdump sudo && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash sandbox

COPY fake_sudo.sh /usr/local/bin/sudo
RUN chmod +x /usr/local/bin/sudo

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /sandbox
RUN chown sandbox:sandbox /sandbox

ENTRYPOINT ["/entrypoint.sh"]
