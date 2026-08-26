# sni-proxy

Прозрачный TCP-прокси на Go: слушает 80/443, по первым байтам соединения определяет протокол (TLS ClientHello или обычный HTTP) и вытаскивает домен назначения — SNI из TLS-хендшейка или заголовок `Host` из HTTP-запроса. Домен резолвится через DNS-over-HTTPS (в обход локального DNS), после чего исходные байты реплеятся дальше на реальный адрес через SOCKS5-апстрим.

Дополнительно поднимает UDP-слушатель на порту HTTPS и отвечает на любой QUIC Initial-пакет пустым Version Negotiation — клиент сразу падает обратно на TCP/TLS, не тратя время на таймаут QUIC.

При старте прокси один раз проверяет, поддерживает ли SOCKS5-апстрим **UDP ASSOCIATE**. Если да — UDP доступен через `ListenPacket()` (можно использовать для будущего проксирования QUIC/других UDP-потоков). Если нет — в логе будет сообщение, и всё работает как раньше только по TCP.

## Как работает

1. `internal/server` — принимает TCP-соединение, по первому байту определяет TLS/HTTP, дочитывает ClientHello или HTTP-заголовки целиком (`internal/sniff`).
2. `internal/resolver` — резолвит домен через DoH (RFC 8484, GET-запрос с `?dns=`), с TTL-кэшем в памяти.
3. `internal/proxy` — открывает соединение до резолвленного IP через SOCKS5-дайлер (`internal/upstream`), реплеит уже прочитанные байты и дальше просто гоняет байты в обе стороны (`io.Copy`) до закрытия любой из сторон.
4. `internal/upstream` — TCP через `golang.org/x/net/proxy`; UDP через собственную реализацию SOCKS5 UDP ASSOCIATE (RFC 1928 §7). Результат probe кэшируется.

## Конфигурация (переменные окружения)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `LISTEN_HTTPS` | `0.0.0.0:443` | TCP-порт для TLS-трафика (маршрутизация по SNI) + тот же порт слушается по UDP для QUIC-редиректа |
| `LISTEN_HTTP` | `0.0.0.0:80` | TCP-порт для обычного HTTP (маршрутизация по `Host`) |
| `SOCKS_URL` | — (обязательна) | SOCKS5-апстрим, например `socks5://user:pass@host:1080` |
| `DOH_SERVER` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS сервер для резолва доменов |
| `DNS_CACHE_TTL` | `5m` | Время жизни записи в DNS-кэше |

## Запуск

```bash
docker compose up -d --build
```

Слушает `80/tcp`, `443/tcp` и `443/udp` в host-режиме (нужны для этого привилегированные порты — образ собирается `CGO_ENABLED=0` под `scratch`, `NET_BIND_SERVICE` выдаётся через `cap_add` в `docker-compose.yml`). Собранный образ также публикуется в GHCR через workflow `.github/workflows/build-image.yml` (ручной запуск).

## UDP / SOCKS

При старте в логе появится одна из строк:

```
[info] SOCKS UDP ASSOCIATE OK — UDP is available
[info] SOCKS upstream supports UDP — ListenPacket() available
```

или

```
[info] SOCKS UDP ASSOCIATE probe failed: ... (UDP unavailable)
[info] SOCKS upstream has no UDP (QUIC will keep falling back to TCP)
```

API для использования UDP из кода:

```go
if dialer.SupportsUDP() {
    pc, err := dialer.ListenPacket() // net.PacketConn через SOCKS UDP relay
    // ...
}
```

Полное проксирование QUIC (извлечение SNI из Initial + пересылка датаграмм) пока не включено — клиенты по-прежнему получают Version Negotiation и падают на TCP/TLS. Когда UDP у SOCKS есть, инфраструктура для этого уже готова.
