FROM alpine:3.10

RUN apk add --no-cache \
    python3 \
    python3-dev \
    samba-client \
    build-base

# get this done early on since it's slow and not likely to change
COPY requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt

RUN adduser -h /adenum -D -u 99999 adenum
ADD --chown=adenum:adenum . /adenum/

WORKDIR /adenum
USER adenum
