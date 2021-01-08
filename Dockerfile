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

FROM alpine
RUN apk update && apk --no-cache add ca-certificates

COPY --from=go-build /app ./

ENTRYPOINT ["./main"]