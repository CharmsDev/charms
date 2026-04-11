FROM ubuntu
RUN apt-get update && apt-get install -y curl
COPY ./bin/charms        /usr/local/bin/
COPY ./bin/charms-prover /usr/local/bin/
CMD ["charms-prover", "server"]
