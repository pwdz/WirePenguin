# FROM gcc:4.9
# COPY . $PATH
# # WORKDIR $PATH

# FROM golang:1.15.0-alpine
# RUN mkdir /app
# ADD . /app
# WORKDIR /app
# # RUN RUN apt-get update && \
# #     apt-get -y install gcc mono-mcs && \
# #     rm -rf /var/lib/apt/lists/*
# RUN go clean --modcache
# RUN go build -o main .
# CMD [*/app/main]
FROM golang:latest AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=1

#Maintainer info
LABEL maintainer="Mohammad Ebrahim Adibzadeh <me.adibzadeh@gmail.com>"

WORKDIR /build

COPY go.mod .
COPY go.sum .

RUN go mod download
RUN apt-get update && apt-get install -y libpcap-dev

COPY . .

RUN go build -o main .

#this step is for CGO libraries
RUN ldd main | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname ./%); cp % ./%;'
RUN mkdir -p lib64 && cp /lib64/ld-linux-x86-64.so.2 lib64/

#Second stage of build
FROM alpine
RUN apk update && apk --no-cache add ca-certificates

COPY --from=builder /build ./

ENTRYPOINT ["./main"]