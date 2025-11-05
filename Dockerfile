# Этап 1: build
FROM golang:1.24.3 AS builder
WORKDIR /app

# Если используешь go.work — раскомментируй следующую строку
# COPY go.work ./
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходники
COPY . .

# Приводим зависимости в порядок (добавит/удалит записи в go.mod/go.sum)
RUN go mod tidy

# Если main в корне:
#   BUILD_TARGET="."
# Если main в подкаталоге (например cmd/sni-proxy):
#   BUILD_TARGET="./cmd/sni-proxy"
ARG BUILD_TARGET=.

# Собираем статический бинарник
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o app ${BUILD_TARGET}

# Этап 2: minimal runtime
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
