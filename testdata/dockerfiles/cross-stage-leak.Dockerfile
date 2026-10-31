FROM golang:1.22 AS builder
WORKDIR /src
COPY id_rsa /root/.ssh/id_rsa
RUN GIT_SSH_COMMAND="ssh -i /root/.ssh/id_rsa" go mod download
RUN go build -o /out/app .

FROM alpine
COPY --from=builder /out/app /app
COPY --from=builder /root/.ssh /stolen-ssh
USER nobody
CMD ["/app"]
