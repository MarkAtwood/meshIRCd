FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -o /meshircd .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /meshircd /usr/local/bin/meshircd
VOLUME /data
EXPOSE 6697
ENTRYPOINT ["meshircd"]
CMD ["--help"]
