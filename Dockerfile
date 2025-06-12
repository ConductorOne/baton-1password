FROM 1password/op:latest
COPY dist/linux_amd64/baton-1password /baton-1password
ENTRYPOINT ["/baton-1password"]

