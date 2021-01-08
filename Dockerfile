FROM golang:latest AS go-build
LABEL maintainer="Mohammad Ebrahim Adibzadeh <me.adibzadeh@gmail.com>"

ENV GO111MODULE=on \
    CGO_ENABLED=1


WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download
RUN apt-get update && apt-get install -y libpcap-dev

COPY . .
RUN go build -o main .

# #this step is for CGO libraries
# RUN ldd main | tr -s '[:blank:]' '\n' | grep '^/' | \
#     xargs -I % sh -c 'mkdir -p $(dirname ./%); cp % ./%;'
# RUN mkdir -p lib64 && cp /lib64/ld-linux-x86-64.so.2 lib64/

#Second stage of build
FROM alpine
RUN apk update && apk --no-cache add ca-certificates

COPY --from=go-build /app ./

ENTRYPOINT ["./main"]