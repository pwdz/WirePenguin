FROM gcc:4.9
COPY . $PATH
# WORKDIR $PATH

FROM golang:1.15.0-alpine
RUN mkdir /app
ADD . /app
WORKDIR /app
# RUN RUN apt-get update && \
#     apt-get -y install gcc mono-mcs && \
#     rm -rf /var/lib/apt/lists/*
RUN go clean --modcache
RUN go build -o main .
CMD [*/app/main]