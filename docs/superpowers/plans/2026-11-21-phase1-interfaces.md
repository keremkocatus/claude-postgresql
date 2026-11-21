# Aşama 1 — Ortak arayüz sözleşmesi

Spec: `docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md`.

Aşama 1 iki plana bölünür; ikisi de bu dosyadaki isimleri **birebir** kullanır.

- **Plan 1a — çekirdek + çoklu PostgreSQL (stdio):** `docs/superpowers/plans/2026-11-21-phase1a-core-postgres.md`
  Sonuç: `ratatoskr serve --config config.yaml` stdio üzerinden çalışır; birden çok PG bağlantısı, policy,
  11 tool (2 ortak + 9 PG), log'a yazan audit. Eski `claude_postgresql` paketi tamamen kaldırılmış olur.
- **Plan 1b — güvenli HTTP:** `docs/superpowers/plans/2026-11-21-phase1b-secure-http.md`
  1a'nın üzerine: SQLite state store, OAuth AS, local + OIDC kimlik, rate-limit, login sayfası,
  SQLite audit sink, `hash-password` CLI, HTTP transport, Dockerfile. 1a bittikten sonra uygulanır.

## Paket ve araçlar

- Modül `src/ratatoskr/`, PyPI adı `ratatoskr-mcp`, CLI `ratatoskr`, sürüm `1.0.0.dev0`.
- Python `>=3.12`. Testler: `tests/unit/` (dış bağımlılık yok) ve `tests/integration/`
  (`@pytest.mark.integration`, testcontainers ile gerçek PostgreSQL; Docker gerekir).
- Komutlar (Windows, repo kökü): `.venv/Scripts/python -m pytest tests/unit -q`,
  `.venv/Scripts/python -m pytest -m integration -q`, `.venv/Scripts/python -m ruff check src tests`,
  `.venv/Scripts/python -m mypy src`.

## `ratatoskr.config`

```python
# config/durations.py
def parse_duration(value: str | int | float | timedelta) -> timedelta: ...   # "30s" "5m" "1h" "30d"; sayı = saniye

# config/models.py   (pydantic v2, tüm modeller model_config = ConfigDict(extra="forbid"))
class Access(enum.IntEnum):
    NONE = 0
    READ = 1
    WRITE = 2

GrantLevel = Literal["read", "write"]

class ServerSettings(BaseModel):
    transport: Literal["stdio", "streamable-http"] = "stdio"
    public_url: AnyHttpUrl | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    metrics_port: int | None = None
    state_path: Path = Path("/data/state.db")
    secret_key: SecretStr | None = None
    allowed_redirect_hosts: list[str] = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]
    stdio_role: str | None = None
    log_level: str = "INFO"

class LocalUser(BaseModel):
    username: str
    password_hash: SecretStr
    groups: list[str] = []

class LocalAuthSettings(BaseModel):
    users: list[LocalUser]

class OidcSettings(BaseModel):
    issuer: AnyHttpUrl
    client_id: str
    client_secret: SecretStr
    scopes: list[str] = ["openid", "email", "profile", "groups", "offline_access"]
    groups_claim: str = "groups"
    subject_claim: str = "email"

class AuthSettings(BaseModel):
    mode: Literal["local", "oidc"]
    access_token_ttl: timedelta = timedelta(hours=1)     # parse_duration ile doğrulanır
    refresh_token_ttl: timedelta = timedelta(days=30)
    local: LocalAuthSettings | None = None
    oidc: OidcSettings | None = None

class PoolSettings(BaseModel):
    min_size: int = 1
    max_size: int = 5
    write_max_size: int = 2

class PgTlsSettings(BaseModel):
    mode: Literal["disable", "require", "verify-ca", "verify-full"] = "verify-full"
    ca_file: Path | None = None
    cert_file: Path | None = None
    key_file: Path | None = None

class PgLimits(BaseModel):
    max_rows: int = 500
    max_response_bytes: int = 65536
    max_query_length: int = 20000

class PostgresConnection(BaseModel):
    kind: Literal["postgres"]
    description: str = ""
    mode: GrantLevel = "read"
    dsn: SecretStr                       # read pool (ve write_dsn yoksa write pool)
    write_dsn: SecretStr | None = None   # yalnız mode: write; lazy write pool'un login'i
    pool: PoolSettings = PoolSettings()
    statement_timeout: timedelta = timedelta(seconds=30)
    allowed_schemas: list[str] = []
    tls: PgTlsSettings | None = None
    limits: PgLimits = PgLimits()

ConnectionConfig = Annotated[PostgresConnection, Field(discriminator="kind")]
# Aşama 2/3 bu union'a PrometheusConnection / LokiConnection ekler.

class RatatoskrConfig(BaseModel):
    server: ServerSettings = ServerSettings()
    auth: AuthSettings | None = None
    roles: dict[str, dict[str, GrantLevel]] = {}
    connections: dict[str, ConnectionConfig]
    # doğrulayıcılar: bağlantı adı regex'i, roles'taki adlar ("*" veya tanımlı), transport kuralları (spec §4)

# config/loader.py
class ConfigError(Exception): ...
def load_config(path: Path, env: Mapping[str, str] | None = None) -> RatatoskrConfig: ...
# ${VAR} ve ${file:/path} interpolasyonu; tanımsız → ConfigError. env None ise os.environ.
```

1a, `transport: streamable-http` doğrulama kurallarını (auth zorunlu, https public_url, secret_key zorunlu,
`--insecure-dev` istisnası) **yazar ve test eder**; ancak HTTP'yi çalıştırmaz — `serve` bu transport'ta
"Plan 1b'de gelecek" hatası değil, `NotImplementedError` yerine açık bir `ConfigError` verir. 1b bunu kaldırır.

## `ratatoskr.auth` (1a yazar: principal + policy)

```python
# auth/principal.py
@dataclass(frozen=True)
class Principal:
    subject: str
    display_name: str
    groups: frozenset[str]
    auth_source: Literal["stdio", "local", "oidc"]

# auth/policy.py
class ConnectionNotFoundError(Exception): ...      # mesaj: "Connection '<ad>' not found."
class InsufficientAccessError(Exception): ...      # mesaj: "Write access required on connection '<ad>'."

class Policy:
    def __init__(self, config: RatatoskrConfig) -> None: ...
    def effective_access(self, principal: Principal, connection: str) -> Access: ...
    def visible_connections(self, principal: Principal) -> list[tuple[str, Access]]: ...   # ada göre sıralı
    def authorize(self, principal: Principal, connection: str, need: Access) -> Access: ...
    # NONE veya tanımsız → ConnectionNotFoundError; etkin < need → InsufficientAccessError

# auth/resolver.py
class PrincipalResolver(Protocol):
    def resolve(self) -> Principal: ...    # mevcut isteğin kimliği; yoksa PermissionError

class StdioPrincipalResolver:              # 1a
    def __init__(self, role: str | None) -> None: ...
    # Principal(subject="stdio", display_name="local stdio user", groups=frozenset({role}) if role else ∅, "stdio")
```

1b ekler: `TokenPrincipalResolver` — `mcp.server.auth.middleware.auth_context.get_access_token()` ile mevcut
access token'ı alır; token, `RatatoskrAccessToken(AccessToken)` alt sınıfıdır ve `subject`, `display_name`,
`groups: list[str]`, `auth_source` alanlarını taşır.

## `ratatoskr.observability.audit` (1a yazar)

```python
AuditResult = Literal["ok", "denied", "error", "timeout"]
# ok: tool cevabını üretti (bağlantı kapalı diyen bir health raporu da ok); denied: kimlik yok, bilinmeyen/yasak
# bağlantı veya yetersiz erişim (backend'e gidilmez); error: backend/PostgreSQL hatası, guard reddi, beklenmeyen
# hata, istemci iptali (error_class="CancelledError"); timeout: deadline doldu veya statement_timeout.
# FastMCP'nin argüman şeması doğrulaması runtime'dan önce reddeder: bu çağrılar audit edilmez.

@dataclass(frozen=True)
class AuditEvent:
    ts: datetime                 # UTC
    subject: str
    auth_source: str
    connection: str | None
    tool: str
    query_text: str | None       # en çok 4096 karakter (kırpılarak)
    query_sha256: str | None     # tam metnin hash'i
    duration_ms: float
    rows: int | None
    result: AuditResult
    error_class: str | None

class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...   # bloklamaz, istisna fırlatmaz

class LogAuditSink: ...          # 1a: logger "ratatoskr.audit", extra={"event": "audit", ...}
class CompositeAuditSink: ...    # 1a: birden çok sink'e dağıtır
```

1b ekler: `SqliteAuditSink` (asenkron kuyruk, 1 sn / 100 olay toplu yazma, kapanışta boşaltma).

## `ratatoskr.backends` (1a yazar)

```python
# backends/base.py
@dataclass(frozen=True)
class HealthResult:
    ok: bool
    latency_ms: float | None
    version: str | None
    error: str | None

@dataclass(frozen=True)
class ConnectionInfo:
    name: str
    kind: str
    description: str
    mode: GrantLevel

class Backend(Protocol):
    kind: ClassVar[str]
    name: str
    async def open(self) -> None: ...
    async def close(self) -> None: ...
    async def health(self) -> HealthResult: ...
    def describe(self) -> ConnectionInfo: ...

# backends/registry.py
class BackendRegistry:
    def __init__(self, config: RatatoskrConfig) -> None: ...
    async def get(self, name: str) -> Backend: ...   # lazy open; açılış hatası 10 sn'de bir yeniden denenir
    def names(self) -> list[str]: ...
    async def close_all(self) -> None: ...

# backends/limits.py
@dataclass(frozen=True)
class Truncated:
    text: str
    truncated: bool
def clamp_text(text: str, max_bytes: int, hint: str) -> Truncated: ...
```

## `ratatoskr.tools.runtime` (1a yazar)

```python
class ToolRuntime:
    def __init__(self, policy: Policy, registry: BackendRegistry,
                 resolver: PrincipalResolver, audit: AuditSink) -> None: ...

    async def run(self, *, tool: str, connection: str, need: Access,
                  call: Callable[[Backend, Access], Awaitable[ToolOutput]],
                  query_text: str | None = None, timeout: float | None = None,
                  on_unavailable: Callable[[BackendUnavailableError], ToolOutput] | None = None) -> ToolResult: ...
    async def run_global(self, *, tool: str, call: Callable[[Principal], Awaitable[ToolOutput]],
                         timeout: float | None = None) -> ToolResult: ...
    # resolve → authorize → registry.get → asyncio.timeout → clamp → audit → ToolResult döner.
    # ConnectionNotFoundError / InsufficientAccessError / zaman aşımı / backend hatası → `Error:` ile başlayan
    # anlaşılır metin (DSN, host, şifre sızdırmadan), is_error=True ve uygun audit sonucu.
    # on_unavailable: registry.get BackendUnavailableError fırlatırsa çıktıyı o üretir (connection_health'in
    # "unavailable" satırı); bu bir hata değildir: is_error=False, audit "ok".
    # Redaksiyon kuralı: başarılı çıktı kullanıcının verisidir, yalnız kırpılır (clamp), asla redact edilmez.
    # Hata metni önce redact sonra clamp edilir. Log'lar ve audit query_text redact edilir.

@dataclass(frozen=True)
class ToolOutput:
    text: str
    rows: int | None = None

@dataclass(frozen=True)
class ToolResult:
    text: str
    is_error: bool
    def to_call_tool_result(self) -> mcp.types.CallToolResult: ...   # TextContent + isError

# Her kayıtlı tool `-> CallToolResult` döner: `return (await runtime.run(...)).to_call_tool_result()`.
# Böylece host'lar hataları isError=true olarak görür.
```

## `ratatoskr.app` ve CLI

```python
# app.py
def build_app(config: RatatoskrConfig, *, resolver: PrincipalResolver, audit: AuditSink,
              auth_server_provider: OAuthAuthorizationServerProvider | None = None,
              auth_settings: mcp.server.auth.settings.AuthSettings | None = None,
              registry: BackendRegistry | None = None) -> FastMCP: ...
# Sahiplik kuralı: registry'yi kim oluşturursa o kapatır. registry=None → build_app oluşturur ve FastMCP
# lifespan'i kapanışta close_all çağırır (stdio). Verilirse lifespan yalnız AppState yield eder; mcp 1.30'da
# streamable-http lifespan'i MCP oturumu başına girer, bu yüzden 1b kendi registry'sini verir ve süreç
# düzeyindeki Starlette lifespan'inde kapatır. Tool'ları tools/common.py ve backends/postgres/tools.py
# içindeki register_*(mcp, runtime) fonksiyonlarıyla kaydeder.

# cli.py — argparse; giriş noktası ratatoskr.cli:main
#   ratatoskr serve [--config PATH] [--insecure-dev]
#   ratatoskr check-config [--config PATH]
#   1b ekler: ratatoskr hash-password
# Config yolu: --config > RATATOSKR_CONFIG > /config/config.yaml
```

## Planlar yazıldıktan sonra eklenenler

Planlar sözleşmeyi bozmadan şunları ekledi (ayrıntı ilgili planda):

- 1a: `load_config(..., *, insecure_dev=False)`; `BackendRegistry(config, *, factory=..., clock=...)`,
  `describe(name)`, `max_response_bytes(name)`; `ToolRuntime.policy`, `.registry`, `run_global(...)`
  (bağlantı parametresi olmayan tool'lar için); `backends/errors.py`, `observability/redact.py`,
  `observability/logging.py`, `audit.build_event`. Tool hataları `Error:` ile başlayan metin ve MCP
  `isError=true` olarak döner (`ToolRuntime.run/run_global -> ToolResult`, tool'lar `CallToolResult` döner).
  Başarılı çıktı redact edilmez; yalnız hata metni, log'lar ve audit `query_text`. `serverInfo.version`
  ratatoskr sürümüdür (FastMCP'de argüman yok; `app._mcp_server.version` atanır, protokol testi korur).
  Sürüm tek kaynaktan: `src/ratatoskr/__init__.py` (hatch dynamic version).
- 1a (sözleşmeye ek): `PostgresConnection.write_dsn: SecretStr | None = None`. Read pool her zaman `dsn` ile,
  lazy write pool `write_dsn` varsa onunla (yoksa `dsn`) bağlanır; TLS ikisine de uygulanır. Yalnız `mode: write`
  ile izinli (aksi config hatası, değer mesajda yer almaz); `${VAR}` / `${file:}` interpolasyonu `dsn` gibi
  çalışır. `check-config` write bağlantılarında "separate write role: yes/no" yazar, DSN'i asla yazmaz.
  asyncpg pool'u bırakılan bağlantıda `RESET ALL` çalıştırdığı için `default_transaction_read_only` ve
  `statement_timeout` startup parametresi olarak verilir.
- 1b: `ServerSettings.trusted_proxies: list[str] = []`, `ServerSettings.audit_retention: timedelta = 90d`;
  `RatatoskrAccessToken` / `RatatoskrRefreshToken(family_id)` `auth/tokens.py` içinde; `TokenPrincipalResolver()`
  argümansız ve mevcut isteğin token'ını okur (`get_access_token()` refresh sonrası eski token döndürür);
  sabit yollar `/login`, `/oauth/callback`, `/healthz`, `/readyz`; varsayılan scope `mcp`; `secret_key` en az
  32 karakter; `public_url` yolsuz origin. `config.models.AuthSettings` ile MCP'nin `AuthSettings`'i aynı adda —
  import alias'ı kullanılır.

## 1b uygulanırken dikkate alınacak review notları

- Uvicorn'un varsayılan `LOGGING_CONFIG`'i `uvicorn` ve `uvicorn.access` logger'larına kendi handler'larını verir
  (`propagate: False`); bu satırlar maskeleyen kök handler'ı atlar. `serve_http` uvicorn'u `log_config=None` ile
  başlatmalı (ya da bu handler'ları temizlemeli) ve bunu bir testle doğrulamalı.
- `setup_logging` kök handler'ları değiştirir; `tests/unit/conftest.py` her testten sonra geri yükler. HTTP testleri
  de bu fixture'a güvenir.

## P3 güvenlik review'undan dokümantasyona (Task 22 / aşama 4) taşınanlar

- Write seviyesindeki `EXPLAIN ANALYZE` ROLLBACK edilir, ama `nextval` ve `dblink` ile yapılan yazmalar geri alınmaz;
  "veri hiç değişmez" denmemeli.
- Read ve write pool aynı DB kullanıcısını paylaşırsa read principal `pg_terminate_backend` ile write bağlantısını
  öldürebilir. `docs/postgres-roles.md` write için ayrı rol önermeli. (Karar: opsiyonel `write_dsn` eklendi; README
  güvenlik modeli bunu öneriyor.)
- Python 3.13 `ssl.create_default_context` `VERIFY_X509_STRICT` açar; `keyUsage` içermeyen iç CA'lar reddedilir
  (libpq kabul eder). Docker imajı 3.12. Dokümante edilecek.
- `tls.mode: require` + `ca_file` CA'yı yok sayar (libpq bunu verify-ca sayar). Dokümante edilecek.
- `check-config` `--insecure-dev` almıyor; 1b'de `serve --insecure-dev`'in kabul ettiği bir config `check-config`'te
  de doğrulanabilmeli (bayrağı ekle).
- Log'lar stdio'da protokolü korumak için **stderr**'e gider (spec §8'deki "stdout" ifadesi HTTP içindir). 1b HTTP'de de
  stderr'de bırakabilir; Docker ikisini de toplar. Bunu "düzeltip" stdio'yu bozmamak için stdout'a geçirme.
- Desteklenen en düşük PostgreSQL sürümü 12 (`attgenerated` PG 12+, `conparentid` PG 11+). README ve config
  referansında yazılacak.

## 1b review notları (ilgili görevlere taşınacak)

- Task 11 (CSRF): imzalanan girdi `f"{request_id}:{cookie}"` belirsiz kodlama; alanları uzunluk önekiyle ya da
  `json.dumps([...])` ile imzala veya `request_id` içinde `:` reddet.
- Task 12 (client_ip / preconditions): `0.0.0.0/0` / `::/0` trusted_proxies için uyarı ver; `::ffff:10.0.0.1`
  gibi IPv4-mapped peer adreslerini `ipv4_mapped` ile aç; `secret_key_problem()` (crypto) preconditions'ta çağrılsın.
- Sealed blob'lar sürüm baytı taşır (`\x01`); store bunları opak bytes olarak saklar.
