FROM alpine:latest as builder
RUN apk add --no-cache gcc make libc-dev gnutls-dev
COPY . /src/
RUN make -C /src clean && make -C /src

FROM alpine:latest as runner
# need coreutils for dd in test.sh (busybox dd doesn't report speed)
RUN apk add --no-cache coreutils gnutls
WORKDIR /srv/ws-tls-inet
COPY --from=builder /src/*.sh /src/*.pem /src/ws /src/tls /src/inet /src/rdwr .
# in my case perf.sh in container is slower than on the host machine
# CMD ./test.sh && ./perf.sh
CMD ./test.sh
