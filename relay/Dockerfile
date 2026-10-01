# The Link relay as a static image. Build from relay/:
#   docker build -t link-relay .
#   docker run -p 8080:8080 link-relay
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/link-relay ./cmd/link-relay

# distroless/static: CA certificates and a nonroot user, no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/link-relay /link-relay
ENV LINK_ADDR=:8080
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/link-relay"]
