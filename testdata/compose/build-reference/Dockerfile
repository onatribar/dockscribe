FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM alpine:3.19
COPY --from=builder /out/app /app
USER app
CMD ["/app"]
