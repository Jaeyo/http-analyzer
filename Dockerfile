FROM golang:1.21

RUN apt-get update
RUN apt-get install -y libpcap-dev

WORKDIR /app
