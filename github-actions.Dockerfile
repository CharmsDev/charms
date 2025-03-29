FROM ubuntu
COPY ./bin/charms /usr/local/bin/
COPY ./prover/bin/charms /usr/local/bin/charms-prover
CMD ["charms", "server"]
