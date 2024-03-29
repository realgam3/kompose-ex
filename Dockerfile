ARG PYTHON_VERSION=3.10
FROM python:${PYTHON_VERSION}-alpine
LABEL maintainer="Tomer Zait <realgam3@gmail.com>"

ARG KOMPOSE_VERSION=1.26.1
ARG EXTRA_REQUIREMENTS=aws

ENV HOME=/root
ENV PATH=${HOME}/.local/bin:${PATH}
COPY . /usr/src/app/
RUN set -eux; \
    pip install --no-cache --user -e "/usr/src/app[${EXTRA_REQUIREMENTS}]"; \
    kompose-ex install --version ${KOMPOSE_VERSION}

ENTRYPOINT [ "kompose-ex" ]
