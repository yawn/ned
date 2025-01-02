FROM golang:1.23.4-alpine3.21 AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=0
ENV SOURCE_DATE_EPOCH=20241218

RUN go build -ldflags="-buildid= -s -w" -mod=readonly -trimpath -o main .

FROM alpine:3.21

WORKDIR /app

COPY --from=builder /app/main .

CMD ["/app/main"] 