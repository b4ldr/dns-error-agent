FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/rfc9567-agent ./cmd/rfc9567-agent

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/rfc9567-agent /usr/local/bin/rfc9567-agent

ENTRYPOINT ["/usr/local/bin/rfc9567-agent"]
