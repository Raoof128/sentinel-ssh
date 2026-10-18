# Disposable SSH target for SentinelSSH end-to-end tests. Synthetic data only; never point tests at a live host.
FROM debian:bookworm-slim
ARG AUTHORIZED_KEY
ARG LARGE=0
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server curl python3 procps findutils coreutils grep \
 && rm -rf /var/lib/apt/lists/*
# Key-only account with a POSIX login shell. '*' disables password login without locking the account for pubkey auth.
RUN useradd -m -s /bin/sh sentinel \
 && usermod -p '*' sentinel \
 && mkdir -p /run/sshd /home/sentinel/.ssh \
 && printf '%s\n' "$AUTHORIZED_KEY" > /home/sentinel/.ssh/authorized_keys \
 && chown -R sentinel:sentinel /home/sentinel/.ssh \
 && chmod 700 /home/sentinel/.ssh \
 && chmod 600 /home/sentinel/.ssh/authorized_keys \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers sentinel\n' > /etc/ssh/sshd_config.d/sentinel.conf
COPY seed.sh entrypoint.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/seed.sh /usr/local/bin/entrypoint.sh && LARGE="$LARGE" /usr/local/bin/seed.sh
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
