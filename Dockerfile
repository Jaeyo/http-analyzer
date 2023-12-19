FROM golang:1.21

# pcap
RUN apt-get update
RUN apt-get install -y libpcap-dev

WORKDIR /app
