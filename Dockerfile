# Этап 1: Сборка бинарника
FROM golang:1.24.3 AS builder

# Создаем рабочую директорию
WORKDIR /app

# Копируем go.mod и go.sum (для кеширования зависимостей)
COPY go.mod go.sum ./
RUN go mod download

# Копируем остальной исходный код
COPY . .

# Сборка бинарника
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app

# Этап 2: Минимальный runtime-образ
FROM gcr.io/distroless/static:nonroot

# Копируем бинарник из предыдущего этапа
COPY --from=builder /app/app /

# Указываем, какой пользователь будет запускать (non-root)
USER root:root

# Точка входа
ENTRYPOINT ["/app"]
