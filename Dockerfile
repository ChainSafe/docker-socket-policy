FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /docker-socket-policy .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /docker-socket-policy /docker-socket-policy
USER 65532:65532
ENTRYPOINT ["/docker-socket-policy"]
