FROM alpine
COPY this-file-does-not-exist.txt /app/config.txt
USER nobody
CMD ["/app/config.txt"]
