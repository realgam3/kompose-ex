FROM python:3.10-alpine
LABEL maintainer="Tomer Zait <realgam3@gmail.com>"

ARG KOMPOSE_VERSION=1.26.1

WORKDIR /usr/src/app/
COPY . .
RUN set -eux; \
    \
    pip install --no-cache .; \
    curl -L https://github.com/kubernetes/kompose/releases/download/v${KOMPOSE_VERSION}/kompose-linux-amd64 \
      -o /usr/local/bin/kompose && chmod +x /usr/local/bin/kompose; \
    rm -fr ./*;

ENTRYPOINT [ "kompose-ex" ]
