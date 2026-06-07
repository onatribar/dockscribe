FROM ubuntu:latest

ARG GITHUB_TOKEN
ENV API_SECRET=hunter2

ADD https://example.com/install.sh /tmp/install.sh
RUN curl -fsSL https://example.com/setup.sh | bash

COPY . /app
WORKDIR /app

CMD ["./run.sh"]
