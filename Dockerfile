FROM --platform=$BUILDPLATFORM golang:1.25.1-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH
ARG VERSION
ARG COMMIT
ARG DATE

ENV CGO_ENABLED=0
ENV GOFLAGS=-trimpath

RUN go build \
    -ldflags="-s -w \
        -X 'github.com/atlet99/ht-notifier/internal/version.Version=${VERSION}' \
        -X 'github.com/atlet99/ht-notifier/internal/version.Commit=${COMMIT}' \
        -X 'github.com/atlet99/ht-notifier/internal/version.Date=${DATE}'" \
    -o /out/server ./cmd/server

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=build /out/server /server
ENTRYPOINT ["/server"]