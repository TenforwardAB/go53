FROM golang:1.20-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN go build -o /go53 ./cmd/server

EXPOSE 53/udp 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -qO- http://localhost:8080 || exit 1

ENTRYPOINT ["/go53"]

