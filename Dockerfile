FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /meshircd .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /meshircd /usr/local/bin/meshircd
VOLUME /data
EXPOSE 6697
ENTRYPOINT ["meshircd"]
CMD ["--help"]
