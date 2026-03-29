# wsst — WebSocket Secure Tunnel

Единый бинарник. Первый аргумент — подкоманда.

```
wsst server  [flags]   # VPS2: HTTP/2 + TLS 1.3 + WSS endpoint
wsst gateway [flags]   # VPS1: SOCKS5 listener + WSS client
wsst version
```

## Архитектура

```
[LAN clients]
    │ SOCKS5
    ▼
[VPS1 gateway]
  • SOCKS5 сервер (:1080)
  • WSS клиент — TLS 1.3 + HTTP/2
  • Мультиплексор потоков
    │
    │  WSS / TLS 1.3 / HTTP2
    │  X-Tunnel-Secret: <token>
    ▼
[VPS2 server]
  • HTTP/2 + TLS 1.3 (:443)
  • Принимает только /tunnel
  • Демультиплексор потоков
  • Dual-stack dial (IPv4 + IPv6)
    │
    ▼
[Интернет]
```

## Сборка

```bash
# Зависимости
go mod tidy

# Сборка (linux/amd64)
make build

# Установка
make install        # → /usr/local/bin/wsst
```

## Деплой

### Общий секрет

```bash
# Генерация секрета
openssl rand -hex 32
```

Запишите в `/etc/wsst/server.env` (VPS2) и `/etc/wsst/gateway.env` (VPS1):

```
TUNNEL_SECRET=ваш_секрет
```

```bash
chmod 600 /etc/wsst/*.env
```

### VPS2 (сервер / exit node)

```bash
# Certbot (если ещё нет)
certbot certonly --standalone -d vps2.example.com

# Бинарник
scp wsst root@vps2:/usr/local/bin/wsst

# systemd
scp deploy/wsst-server.service root@vps2:/etc/systemd/system/
ssh root@vps2 "systemctl daemon-reload && systemctl enable --now wsst-server"
```

### VPS1 (шлюз / SOCKS5)

```bash
scp wsst root@vps1:/usr/local/bin/wsst
scp deploy/wsst-gateway.service root@vps1:/etc/systemd/system/
ssh root@vps1 "systemctl daemon-reload && systemctl enable --now wsst-gateway"
```

### Проверка

```bash
# На VPS1 проверяем SOCKS5
curl --socks5 localhost:1080 https://ifconfig.me

# Должен вернуть IP адрес VPS2
```

## Флаги

### server

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-server` | — | `wss://host/path` — извлекается только путь `/tunnel` |
| `-addr` | `:443` | Адрес для прослушивания |
| `-cert` | `/etc/letsencrypt/live/…/fullchain.pem` | TLS сертификат |
| `-key` | `/etc/letsencrypt/live/…/privkey.pem` | TLS ключ |
| `-secret` | — | Общий секрет (обязательно) |

### gateway

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `-server` | — | WSS URL сервера (обязательно) |
| `-socks` | `:1080` | Адрес SOCKS5 сервера |
| `-secret` | — | Общий секрет (обязательно) |
| `-insecure` | false | Пропустить проверку TLS (только разработка) |

## Особенности

- **TLS 1.3** — принудительно, без downgrade до 1.2
- **HTTP/2** — WebSocket Upgrade через HTTP/2 CONNECT (RFC 8441)
- **IPv4 → IPv6** — VPS1 может подключаться к VPS2 по IPv6 через URL `wss://[2001:db8::1]/tunnel`
- **Dual-stack** — VPS2 дозванивается до целей по IPv4 и IPv6 автоматически
- **Реконнект** — gateway переподключается с exponential backoff (1s → 60s)
- **Мультиплексинг** — все SOCKS5 соединения идут через одно WSS соединение
- **Путь туннеля** — задаётся через `-server wss://host/path`, любой другой путь возвращает `200 ok` (антифинансирование)
