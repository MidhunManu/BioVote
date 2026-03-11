# ── Build Stage ──────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o voter-api .

# ── Production Stage ─────────────────────────────────────────
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata
ENV TZ=Asia/Kolkata

WORKDIR /app
COPY --from=builder /app/voter-api .

EXPOSE 8080

CMD ["./voter-api"]
