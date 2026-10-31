FROM python:2.7 AS builder
ARG DEPLOY_TOKEN
RUN pip install -r requirements.txt

FROM node:14 AS unused
RUN echo "this stage is never referenced by a later COPY --from"

FROM python:2.7
ARG BUILD_SECRET
ARG DEPLOY_TOKEN
ENV BUILD_SECRET=$BUILD_SECRET
ENV AWS_KEY=AKIAIOSFODNN7EXAMPLE
ENV SESSION_HASH=aZ9kQ7mX2vB8nC4wE6rT1yU3iO5pL0sD

COPY id_rsa /root/.ssh/id_rsa
RUN curl -fsSL -H "Authorization: Bearer $DEPLOY_TOKEN" https://api.example.com/deploy
RUN rm /root/.ssh/id_rsa

CMD ["python", "app.py"]
