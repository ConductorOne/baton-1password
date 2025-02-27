FROM debian:11-slim AS builder

RUN apt update && apt install -y curl gnupg && \
    curl -sS https://downloads.1password.com/linux/keys/1password.asc | \
    gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/$(dpkg --print-architecture) stable main" | \
    tee /etc/apt/sources.list.d/1password.list && \
    apt update && apt install -y 1password-cli && \
    rm -rf /var/lib/apt/lists/*

FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=builder /usr/bin/op /usr/bin/op

ENTRYPOINT ["/baton-1password"]
COPY baton-1password /