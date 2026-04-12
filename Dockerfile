ARG GO_VERSION=1.26.2

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bypassdpi ./cmd/bypassdpi

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /bypassdpi /bypassdpi

USER 65532:65532

ENTRYPOINT ["/bypassdpi"]
