# Build stage: compile the chaincode statically with no CGO
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -o /flex-cc .

# Runtime stage: minimal Alpine image
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /flex-cc /flex-cc
EXPOSE 9999
ENTRYPOINT ["/flex-cc"]
