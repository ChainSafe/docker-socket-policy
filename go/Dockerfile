FROM --platform=linux/amd64 stagex/pallet-go@sha256:d7e9e39ab6e9c254f5eacf3ae5496024dc95e4deaf1402a67fda96f2da007558 AS build

ARG VERSION=dev

ENV SOURCE_DATE_EPOCH=1
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN --network=none \
  go build \
    -mod=mod \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid= -X main.Version=${VERSION}" \
    -o /docker-socket-policy \
    .

FROM --platform=linux/amd64 stagex/core-filesystem@sha256:cd3a66471ce1f630fa77d5c9bd9829f9f9fab6302a1aaa64d67b74f1f069b750 AS run
COPY --from=build /docker-socket-policy /docker-socket-policy
USER 65532:65532
ENTRYPOINT ["/docker-socket-policy"]
