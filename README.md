# sni-proxy

Прозрачный TCP/UDP-прокси на Go: слушает 80/443, по первым байтам соединения определяет протокол (TLS ClientHello или обычный HTTP) и вытаскивает домен назначения — SNI из TLS-хендшейка или заголовок `Host` из HTTP-запроса. Домен резолвится через DNS-over-HTTPS (в обход локального DNS), после чего исходные байты реплеятся дальше на реальный адрес через SOCKS5-апстрим.

## UDP / QUIC

При старте прокси один раз проверяет, поддерживает ли SOCKS5-апстрим **UDP ASSOCIATE**:

- **UDP есть** — QUIC/HTTP3 проксируется через SOCKS: из Initial-пакета достаётся SNI (`quicsni`), домен резолвится через DoH, датаграммы гоняются через UDP ASSOCIATE. Клиент ходит только на IP sni-proxy (как и для TCP).
- **UDP нет** — на любой QUIC Initial отвечает пустым Version Negotiation; клиент сразу падает на TCP/TLS без таймаута.

Если SNI из QUIC Initial извлечь не удалось — тоже отправляется Version Negotiation (fallback на TCP).

## Как работает

1. `internal/server` — TCP: по первому байту TLS/HTTP, sniff SNI/Host. UDP: либо QUIC-прокси через SOCKS, либо Version Negotiation.
2. `internal/resolver` — DoH (RFC 8484), TTL-кэш в памяти.
3. `internal/proxy` — TCP-туннель через SOCKS CONNECT; UDP-туннель через SOCKS UDP ASSOCIATE (сессии по client addr, idle 90s).
4. `internal/upstream` — TCP через `golang.org/x/net/proxy`; UDP — своя реализация ASSOCIATE (RFC 1928 §7).

## Конфигурация (переменные окружения)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `LISTEN_HTTPS` | `0.0.0.0:443` | TCP (TLS/SNI) + UDP (QUIC) на этом адресе |
| `LISTEN_HTTP` | `0.0.0.0:80` | TCP для обычного HTTP (Host) |
| `SOCKS_URL` | — (обязательна) | SOCKS5-апстрим, например `socks5://user:pass@host:1080` |
| `DOH_SERVER` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS |
| `DNS_CACHE_TTL` | `5m` | TTL DNS-кэша |

## Запуск

```bash
docker compose up -d --build
```

Слушает `80/tcp`, `443/tcp` и `443/udp` в host-режиме. Образ: `CGO_ENABLED=0`, `scratch`, `cap_add: NET_BIND_SERVICE`.

Клиент по DNS sniff всегда ходит на IP sni-proxy. Xray/SOCKS клиенту не виден — sni-proxy сам ходит на `SOCKS_URL` (часто `127.0.0.1:1080` или docker-сеть).
