# AGENTS.md — Go backend (workspace/api)

Карта архитектуры Go-бэкенда мессенджера. См. также корневой `../../AGENTS.md` для
кросс-проектных инвариантов (общих с Swift-клиентом).

---

## 1. Обзор

- **Язык & Рантайм:** Go 1.22+
- **Транспорт & Криптография:** TCP + length-prefix framing (4 байта big-endian),
  Noise IK handshake (`Noise_IK_25519_ChaChaPoly_SHA256`)
- **Wire-протокол:** FlatBuffers (`../../proto/schema.fbs`)
- **Архитектурный паттерн:** Clean Architecture (Ports & Adapters)
- **CLI фреймворк:** Cobra (`internal/transport/cli`)
- **Хранилища:** PostgreSQL (постоянные данные), Redis (сессии/QR-логин/pub-sub)

---

## 2. Карта слоёв (`internal/`)

```
internal/
├── domain/          ← Разбит по поддоменам. В каждом: entity.go + interfaces.go. НОЛЬ внешних зависимостей (только stdlib)!
├── usecase/         ← Бизнес-логика. Зависит ТОЛЬКО от internal/domain/*.
├── infrastructure/  ← Реализации портов: БД, email, Redis, серверные ключи, nodeid.
└── transport/       ← CLI (cobra), TCP, framing, Noise IK, HTTP (OAuth), FlatBuffers. Вызывает usecase.
```

Правило зависимостей: `transport → usecase → domain ← infrastructure`.

### Поддомены (`internal/domain/<context>/`)

| Поддомен | Назначение |
|---|---|
| `account` | Сущность `Account`, `Repository`, `ConfirmationCodeRepository`, `EmailSender` |
| `authidentity` | `AuthIdentity`, провайдеры (email, github), `Repository` |
| `device` | `Device` (метаданные + fingerprint), `Repository`, `NewDeviceNotifier` |
| `oauth` | `GithubUser`, порт `GithubClient` |
| `qrlogin` | `Ticket`, статусы, PubSub-события, `Repository`, `EventPublisher` |
| `session` | `Session`, `Repository` (управление сессиями и TTL) |
| `message` | `Message`, `MessageState`, `Repository` |
| `serverkey` | `Repository` (загрузка серверного X25519 keypair) |
| `updatelog` | Update log / gap-recovery инварианты (MTProto-style seq counters) |

### Usecase (`internal/usecase/`)

| Файл | Назначение |
|---|---|
| `email_auth.go` | Passwordless email OTP: регистрация, отправка/подтверждение кода |
| `github_auth.go` | GitHub OAuth с auto-link по verified email |
| `qrlogin.go` | QR-логин (WhatsApp Web / Telegram Desktop паттерн), Redis pub/sub push |
| `session.go`, `session_management.go` | NewSession/ResumeSession, TTL, ротация |
| `heartbeat.go` | Ping/Pong keepalive |
| `message.go` | Отправка/доставка сообщений |
| `device_upsert.go` | Регистрация/обновление устройства (fingerprint, метаданные) |
| `updatelog.go` | GetDifference / DifferenceAck — gap recovery для клиентов |

### Infrastructure (`internal/infrastructure/`)

| Пакет | Назначение |
|---|---|
| `postgres` | Репозитории: `account_repo.go`, `auth_identity_repo.go`, `device_repo.go`, `session_repo.go`, `code_repo.go` |
| `redis` | `qrlogin_repo.go` (тикеты), `qrlogin_pubsub.go` (cross-instance push) |
| `redisclient` | Единая обёртка Redis-клиента |
| `email` | `LogEmailSender` (OTP, для dev), `SMTPClient`/`SMTPNewDeviceNotifier` (прод) |
| `oauth` | `GithubClient` поверх OAuth2 |
| `serverkey` | `FileServerKeyRepository` — статический X25519 keypair сервера |
| `nodeid` | Персистентный UUID узла (диск-кэш для local dev) |
| `logger` | Structured logging (Logrus), `Init`/`ToContext`/`FromContext` |
| `sessioncleanup` | Фоновый воркер очистки истёкших сессий по TTL |
| `memory` | In-memory `SessionRepository` для тестов |

### Transport (`internal/transport/`)

| Пакет | Назначение |
|---|---|
| `framing.go` / `connection.go` / `listener.go` | Голый TCP: length-prefix framing, `Connection` (блокирующий API), accept loop |
| `registry.go` | `ConnectionRegistry` |
| `router.go` | `MessageRouter` — диспетчеризация application-фреймов в usecase |
| `noiseik/` | `ServerHandshake`, `ClientHandshake`, `Conn` — зеркалит Swift-клиент 1:1 |
| `http/` | Chi-сервер для GitHub OAuth redirect (`server.go`, `oauth_handler.go`) |
| `cli/` | Cobra: `serve`, `keygen`, `migrate`, `version` |

Прочее: `cmd/app/main.go` — единая точка входа, делегирует в `cli.Execute()`.
`migrations/postgres/` — plain SQL (`.up.sql`/`.down.sql`).

---

## 3. Ключевые инварианты

1. **Доменные поддомены:** `entity.go` + `interfaces.go`, ноль внешних зависимостей.
2. **Правило зависимостей:** `transport → usecase → domain ← infrastructure`. Никогда наоборот.
3. **Единая точка входа:** `cmd/app/main.go` → `cli.Execute()`.
4. **FlatBuffers `union Body` строго append-only** (см. корневой AGENTS.md и README.md
   для полной таблицы индексов). Тест `TestUnionBodyIndicesAreStable` в
   `internal/protocol/smoke_test.go` фиксирует текущие значения — если упал после
   правки схемы, порядок нарушен.
5. **`internal/protocol/generated/` — артефакт сборки, не коммитится.** Единственный
   способ обновить: `make gen` (см. `.gitignore`). `make build`/`make test`/`make run`
   зависят от `make gen` автоматически.
6. **Noise handshake зеркалируется на Swift-клиенте.** Изменения в `internal/noiseik/`
   требуют синхронного изменения в
   `../macOS-swift/submodules/AirlanceClient/Sources/AirlanceClient/Noise/`.

---

## 4. Команды сборки и тестирования

```bash
make gen     # Сгенерировать Go-код из ../../proto/schema.fbs (./scripts/gen-fbs.sh)
make build   # gen + go build ./...
make test    # gen + go test ./...
make run     # gen + go run ./cmd/app serve
```

### GOPROXY (ограниченная сеть)

Если `go mod tidy`/`go get` падает с `403 Forbidden: proxy.golang.org`:

```bash
GOPROXY=direct GOSUMDB=off go mod tidy
```

### Версия flatc

Кодген зависит от версии `flatc` (в разработке — `2.0.8`). `brew install flatbuffers`
может поставить более новую (24.x+) с другим кодгеном. Перед `make gen` сверь
`flatc --version`; при расхождении зафиксируй `flatbuffers@2` или прогони `make gen` +
`go test ./...` перед обновлением версии в README.

---

## 5. Известные незакрытые вопросы (архитектурные, не баги)

- **Graceful shutdown** `ListenAndServe` не реализован — блокируется до ошибки `Accept`.
  Форма API нужна вместе с Connection ID registry / heartbeat manager.
- **Паника внутри `Handler`** не перехватывается — уронит процесс. Решение (глушить
  молча или пробрасывать) откладывается до Message Router.