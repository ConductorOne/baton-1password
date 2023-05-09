FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-1password"]
COPY baton-1password /