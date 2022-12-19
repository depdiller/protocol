FROM golang:alpine as builder
ENV GOOS linux
RUN apk add --no-cache make
WORKDIR /app
COPY . .
RUN make build

FROM alpine
WORKDIR /app
COPY --from=builder /app/gen /app/verifier /app/crack ./
COPY --from=builder /app/txt ./txt
