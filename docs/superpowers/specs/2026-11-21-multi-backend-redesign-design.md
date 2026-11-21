# Çoklu Backend MCP Sunucusu — Tasarım

- **Tarih:** 2026-11-21
- **Durum:** Onay bekliyor
- **Kapsam:** `claude-postgresql` projesinin, birden fazla PostgreSQL, Prometheus ve Loki bağlantısına güvenli,
  çok kullanıcılı erişim sağlayan genel bir MCP sunucusuna dönüştürülmesi.

## 1. Amaç ve hedef kitle

Ekipler Claude'u (claude.ai connector, Claude Desktop, Claude Code) kendi altyapılarına bağlar: veritabanlarını
sorgular, metriklere ve loglara bakar, bunları tek konuşmada ilişkilendirir.

- **Open-source varsayılanı basit:** tek `docker compose up`, yerel kullanıcılar, tek config dosyası.
- **Ekip kullanımı birinci sınıf:** OIDC (ilk hedef Authentik), gruba göre bağlantı yetkisi, audit kaydı.
- Proje 0.1.0 olduğu için kırıcı değişiklik kabul edilir; 1.0.0 olarak yayımlanır.

### Hedef dışı (bu tasarımda yok)

- Admin web arayüzü, kişisel API token'ları.
- Birden fazla replika / yatay ölçekleme (state deposu arayüzü bunu ileride mümkün kılar).
- Yazma işlemleri için iki aşamalı onay (MCP istemcilerinin tool onayı + `destructiveHint` yeterli).
- `PG_MCP_*` env değişkenleriyle geriye uyumluluk.
- Bundled Authentik (yalnız kurulum rehberi).

## 2. İsim

Adaylar (2026-11-21 itibarıyla PyPI'da boş; GitHub org/repo ve GHCR adı ayrıca kontrol edilmeli):

| Ad | Not |
|---|---|
| **`infraquery`** (öneri) | Ne yaptığını söylüyor: altyapıyı sorgula. CLI ve paket adı olarak kısa. |
| `opslens` | Gözlemlenebilirlik çağrışımı güçlü, DB tarafını daha az anlatıyor. |
| `opsbridge` | "Claude ile altyapı arasında köprü"; biraz jenerik. |
| `stackprobe` | Akılda kalıcı, ama "probe" yazma işlemini çağrıştırmıyor. |

Karar verilene kadar bu dokümanda paket adı `<pkg>` olarak geçer. Seçilen ad: PyPI paketi, Python modülü,
CLI komutu, GHCR imajı (`ghcr.io/<owner>/<pkg>`) ve GitHub repo adı olarak kullanılır.

## 3. Mimari

Tek süreç, tek FastMCP uygulaması. Backend türleri ortak bir arayüzü uygulayan modüllerdir; yetki, audit, limit
ve formatlama ortak katmanda bir kez yazılır. Alternatifler (backend başına ayrı sunucu + gateway; hazır MCP
sunucularını birleştirmek) tek yetki modeli ve tek audit izi sağlayamadığı için elendi.

### 3.1 Modül yapısı

```
src/<pkg>/
  app.py                FastMCP kurulumu, lifespan, tool kaydı, custom route'lar
  cli.py                `<pkg> serve | hash-password | check-config`
  config/
    loader.py           YAML okuma, ${ENV} ve ${file:/path} interpolasyonu
    models.py           pydantic modelleri ve doğrulama
  auth/
    oauth_server.py     MCP OAuth AS (DCR, code+PKCE, token, revoke) — Store destekli
    identity/base.py    IdentityProvider arayüzü → Principal
    identity/local.py   yerel kullanıcılar (argon2id)
    identity/oidc.py    OIDC RP (Authentik), groups claim, upstream refresh
    policy.py           Principal → bağlantı → etkin erişim seviyesi
    ratelimit.py        IP ve kullanıcı bazında kayan pencere + üstel bekleme
    web.py              login/callback sayfaları, CSRF, güvenlik başlıkları
  state/
    store.py            Store arayüzü (client, token, rate-limit, audit)
    sqlite.py           aiosqlite, WAL, tek yazıcı
    audit.py            asenkron kuyruk, toplu yazma, log'a yansıtma
  backends/
    base.py             Backend protokolü
    registry.py         config → lazy backend örnekleri
    limits.py           satır / seri / bayt / zaman aralığı kırpma
    timeparse.py        RFC3339 ve göreli zaman (now-1h)
    postgres/           backend.py, tools.py, guard.py, introspection.py
    prometheus/         client.py (httpx), tools.py, summarize.py
    loki/               client.py (httpx), tools.py
  tools/common.py       list_connections, connection_health
  observability/        logging.py (JSON + maskeleme), metrics.py, health.py
```

Her dosya tek sorumluluk taşır; mevcut 345 satırlık `server.py`'deki config, auth ve tool kaydı karışımı
dağıtılır. Mevcut `formatters.py`, `database.py` ve `tools/schema.py` içerikleri `backends/postgres/` altına
taşınıp uyarlanır; `query_history.py` audit ile değiştirilir ve kaldırılır.

### 3.2 Backend protokolü

```python
class Backend(Protocol):
    kind: ClassVar[str]                 # "postgres" | "prometheus" | "loki"
    name: str                           # config'teki bağlantı adı
    async def open(self) -> None: ...   # ilk kullanımda çağrılır
    async def close(self) -> None: ...
    async def health(self) -> HealthResult: ...   # erişilebilirlik, gecikme, sürüm
    def describe(self) -> ConnectionInfo: ...     # list_connections için
```

Tool'lar backend türüne göre gruplanır (`backends/<kind>/tools.py`) ve kayıt sırasında ortak bir sarmalayıcıdan
geçer. Sarmalayıcı her çağrıda: kimliği çözer, yetkiyi kontrol eder, backend'i registry'den alır (gerekirse
`open`), zaman aşımını uygular, sonucu limitlere göre kırpar, audit olayını kuyruğa atar.

### 3.3 İstek akışı

1. MCP SDK Bearer token'ı doğrular → `AccessToken` → `Principal(subject, display_name, groups)`.
2. `policy.authorize(principal, connection, need)` — `need` tool'a göre `read` veya `write`.
   Bağlantı yoksa **veya** yetki yoksa aynı hata döner: `Connection '<ad>' not found.`
3. Backend çağrısı; istemci tarafı zaman aşımı + backend tarafı zaman aşımı (PG `statement_timeout`).
4. Sonuç kırpılır; kırpıldıysa sonuna neyin neden kırpıldığını ve nasıl daraltılacağını söyleyen not eklenir.
5. Audit olayı: zaman, subject, bağlantı, tool, sorgu metni (en çok 4 KB) ve SHA-256 hash'i, süre, satır
   sayısı, sonuç (`ok | denied | error | timeout`), hata sınıfı.

### 3.4 Dayanıklılık

- Backend'ler lazy açılır; erişilemeyen bir backend sunucunun açılmasını engellemez.
- Açılış hatası bağlantı bazında tutulur; sonraki çağrıda yeniden denenir (en sık 10 sn'de bir).
- `close` lifespan sonunda tüm açık backend'lerde çağrılır.

## 4. Konfigürasyon

Tek YAML dosyası (varsayılan `/config/config.yaml`, `--config` veya `<PKG>_CONFIG` ile değiştirilir).
Secret'lar dosyada düz metin olarak tutulmaz: `${ENV_ADI}` veya `${file:/run/secrets/ad}` ile verilir.
Tanımsız bir değişkene referans config hatasıdır (sessiz boş değer yok). `<pkg> check-config` dosyayı
doğrular ve hiçbir secret'ı yazdırmadan özet basar.

```yaml
server:
  public_url: https://mcp.sirket.com        # HTTP transport'ta zorunlu, https olmalı
  transport: streamable-http                # stdio | streamable-http
  host: 0.0.0.0
  port: 8000
  metrics_port: 9100                        # iç port; proxy'ye açılmaz. null = kapalı
  state_path: /data/state.db
  secret_key: ${SERVER_SECRET_KEY}          # zorunlu (HTTP); upstream token şifreleme ve CSRF imzası
  allowed_redirect_hosts: [claude.ai, claude.com, localhost, 127.0.0.1]
  stdio_role: admins                        # yalnız transport: stdio iken kullanılır

auth:
  mode: oidc                                # local | oidc
  access_token_ttl: 1h
  refresh_token_ttl: 30d
  oidc:
    issuer: https://auth.sirket.com/application/o/mcp/
    client_id: ${OIDC_CLIENT_ID}
    client_secret: ${OIDC_CLIENT_SECRET}
    scopes: [openid, email, profile, groups, offline_access]
    groups_claim: groups
    subject_claim: email
  local:
    users:
      - username: kerem
        password_hash: ${KEREM_PASSWORD_HASH}   # `<pkg> hash-password` ile üretilir
        groups: [admins]

roles:                                      # grup adı → { bağlantı adı | "*": read | write }
  admins:  { "*": write }
  devops:  { prod-pg: read, staging-pg: write, prom-main: read, loki-main: read }
  analyst: { prod-pg: read }

connections:
  prod-pg:
    kind: postgres
    description: "Ana uygulama veritabanı (prod)"
    mode: read                              # read | write; varsayılan read
    dsn: ${PROD_PG_DSN}
    pool: { min_size: 1, max_size: 5 }
    statement_timeout: 30s
    allowed_schemas: [public]               # yalnız keşif tool'larını süzer
    tls: { mode: verify-full, ca_file: /config/certs/prod-ca.pem }
    limits: { max_rows: 500 }
  staging-pg:
    kind: postgres
    mode: write
    dsn: ${STAGING_PG_DSN}
  prom-main:
    kind: prometheus
    url: http://prometheus:9090
    auth: { type: bearer, token: ${PROM_TOKEN} }    # none | basic | bearer
    headers: {}
    limits: { max_series: 100 }
  loki-main:
    kind: loki
    url: http://loki:3100
    tenant: ${LOKI_TENANT}                  # X-Scope-OrgID; opsiyonel
    limits: { max_lines: 500, max_line_bytes: 2048, max_range: 24h }
```

Doğrulama kuralları:

- Bağlantı adları `^[a-z0-9][a-z0-9_-]{0,62}$`.
- `roles` içindeki her bağlantı adı ya `*` ya da tanımlı bir bağlantı olmalı.
- `transport: streamable-http` iken `auth` ve https `public_url` zorunlu. Tek istisna `--insecure-dev` bayrağı
  (yalnız `localhost` bind'ında ve log'da her açılışta uyarıyla).
- `mode: local` ise en az bir kullanıcı; `mode: oidc` ise `issuer`, `client_id`, `client_secret` zorunlu.
- Süreler `30s`, `5m`, `1h`, `30d` biçiminde.

## 5. Kimlik ve yetki

### 5.1 Principal ve etkin yetki

`Principal(subject, display_name, groups, auth_source)`.

`etkin_yetki(principal, bağlantı) = min(max(grupların grant'leri), bağlantı.mode)`, sıralama `none < read < write`.
Hiçbir grant eşleşmezse `none` (deny-by-default). `mode: read` bağlantıda admin bile yazamaz.

Yetki **her çağrıda** config'ten hesaplanır; token'a gömülmez. Grupların kaynağı:

- `local`: config'teki kullanıcı kaydı (her çağrıda okunur → değişiklik config yeniden yüklenince anında etkili).
  Config yeniden yükleme: `SIGHUP` veya container restart.
- `oidc`: login'de alınan `groups` claim'i, token kaydında saklanır ve her refresh'te yenilenir (5.3).

### 5.2 OAuth akışı (Claude ↔ sunucu ↔ Authentik)

Sunucu, MCP istemcisine karşı OAuth 2.1 authorization server; Authentik'e karşı OIDC relying party'dir.

1. **DCR:** İstemci `/register` ile kaydolur. Her `redirect_uri`'nin host'u `allowed_redirect_hosts`
   içinde olmalı; `localhost`/`127.0.0.1` dışındakiler https olmalı. Aksi halde kayıt reddedilir.
   Kayıt endpoint'i IP bazında rate-limit'lidir.
2. **Authorize:** PKCE (S256) zorunlu. Sunucu bekleyen yetkilendirmeyi state store'a yazar (10 dk TTL).
   - `local`: login formu. Form, istemci adını ve redirect host'unu gösterir; CSRF token'ı taşır.
   - `oidc`: Authentik'e yönlendirme (authorization code + PKCE + `state` + `nonce`). Callback'te ID token
     imzası, `iss`, `aud`, `nonce`, `exp` doğrulanır; `subject_claim` ve `groups_claim` okunur.
3. **Kod:** Tek kullanımlık, 5 dk TTL, istemci ve redirect_uri'ye bağlı.
4. **Token:** Opak, 32 bayt rastgele. Store'da yalnız SHA-256 hash'i tutulur.
   - Access token: varsayılan 1 saat.
   - Refresh token: varsayılan 30 gün, her kullanımda döndürülür. Aynı token aileden ikinci kez kullanılırsa
     (reuse) tüm aile iptal edilir ve audit'e `token_reuse_detected` yazılır.
5. **Revoke:** `/revoke` desteklenir; aileyi iptal eder.

### 5.3 Hesaptan çıkarma (OIDC)

Login'de Authentik'ten alınan upstream refresh token şifrelenmiş olarak saklanır (AES-GCM; anahtar
`server.secret_key`'den türetilir, tanımlı değilse açılışta hata). Bizim refresh endpoint'imiz çağrıldığında önce upstream refresh yapılır ve
userinfo/ID token'dan gruplar yeniden okunur. Upstream refresh başarısızsa (kullanıcı pasif, oturum iptal)
bizim token ailemiz de iptal edilir. Sonuç: Authentik'te yapılan değişiklik en geç bir access token ömrü
(varsayılan 1 saat) içinde etkili olur.

### 5.4 Saldırı yüzeyi önlemleri

| Tehdit | Önlem |
|---|---|
| URL'yi bilen herkesin erişmesi | HTTP transport auth olmadan başlamaz |
| Şifre deneme | IP başına ve kullanıcı başına sınır (örn. 5/dk), ardından üstel bekleme; audit kaydı |
| Kötü niyetli istemci kaydı ile token çalma | redirect_uri host allowlist'i, PKCE zorunlu |
| Token sızıntısı (DB dosyası) | Yalnız hash saklanır; upstream token şifreli |
| Çalınan refresh token | Rotasyon + reuse detection |
| CSRF / clickjacking (login sayfası) | CSRF token, `SameSite=Strict` çerez, CSP `frame-ancestors 'none'`, `X-Content-Type-Options` |
| DNS rebinding | MCP SDK koruması açık; `public_url` host'u izinli |
| Bağlantı adlarının sızması | Yetkisiz ve var olmayan bağlantı için aynı hata; `list_connections` süzülmüş |
| Secret'ların log'a düşmesi | Log formatter DSN şifrelerini, `Authorization` header'larını ve token'ları maskeler |
| Ham TLS'siz trafik | `public_url` https olmalı; TLS reverse proxy'de (Caddy) sonlanır |

### 5.5 stdio modu

Auth yoktur (süreci başlatan yerel kullanıcıdır). Principal `stdio` olur ve `server.stdio_role` grubuna sahip
sayılır. HTTP route'ları (login, register) kayıt edilmez.

## 6. Tool setleri

Toplam 19 tool; bağlantı sayısı arttıkça değişmez. Her backend tool'unun ilk parametresi `connection`'dır.
Okuma tool'ları `readOnlyHint: true`, `pg_execute` `destructiveHint: true` annotation'ı taşır.

### 6.1 Ortak

| Tool | Yetki | Açıklama |
|---|---|---|
| `list_connections()` | — | Kullanıcının etkin yetkisi `none` olmayan bağlantılar: ad, tür, açıklama, etkin yetki |
| `connection_health(connection?)` | read | Bir veya tüm görünür bağlantılar: erişilebilir mi, gecikme, sunucu sürümü |

### 6.2 PostgreSQL

| Tool | Yetki | Açıklama |
|---|---|---|
| `pg_list_schemas` | read | Sistem dışı şemalar (`allowed_schemas` ile süzülür) |
| `pg_list_tables(schema)` | read | Tablolar, view'lar, tahmini satır sayısı |
| `pg_describe_table(table, schema)` | read | Kolonlar, PK, FK, index'ler, constraint'ler — tek çağrı |
| `pg_query(sql, params?)` | read | Okuma sorgusu |
| `pg_execute(statements)` | write | `[{sql, params?}]`; tek atomik transaction |
| `pg_explain(sql, params?, analyze=false, buffers=false)` | read / write | Plan (aşağıya bakın) |
| `pg_activity` | read | Çalışan sorgular ve bekleyen kilitler |
| `pg_table_stats(schema, table?)` | read | Boyut, scan, tuple, vacuum/analyze istatistikleri |
| `pg_server_info` | read | Sürüm, veritabanları, mevcut DB boyutu |

**Read modunun zorlanması (guard.py).** Regex'e güvenilmez; katmanlar:

1. **Pool ayrımı:** Her PG bağlantısının bir *read pool*'u vardır; bağlantıları açılışta
   `SET default_transaction_read_only = on` ve `statement_timeout` alır. `pg_query`, `pg_explain(analyze=false)`
   ve tüm keşif tool'ları her kullanıcı için bu pool'u kullanır. Yalnız `mode: write` bağlantılarda ek bir
   küçük *write pool* açılır (`pool.write_max_size`, varsayılan 2, lazy) ve yalnız `pg_execute` ile write
   yetkili `pg_explain(analyze=true)` onu kullanır.
2. **Tek ifade:** Okuma yolunda sorgular her zaman extended protocol (prepared statement) ile gönderilir;
   bu protokol tek ifadeye izin verir. Böylece `COMMIT; DELETE ...` gibi transaction'dan kaçma denemeleri
   protokol seviyesinde imkânsızdır.
3. `pg_query` her zaman `BEGIN READ ONLY` transaction içinde çalışır ve sonunda ROLLBACK edilir.
4. Dokümantasyon her bağlantı için `GRANT`'leri kısıtlı bir DB rolü önerir — **asıl sınır budur.**
   Read-only transaction, yeni bir bağlantı açan uzantıları (`dblink`, `postgres_fdw`) durdurmaz; bunlar
   ancak DB rolüyle engellenir ve `docs/postgres-roles.md` bunu açıkça yazar.
5. Hafif bir ön kontrol (boş değil, uzunluk sınırı) yalnız erken ve anlaşılır hata için kalır.
   Mevcut tehlikeli fonksiyon listesi (`pg_read_file`, `COPY ... TO PROGRAM` vb.) `pg_execute` için ön kontrol
   olarak korunur, ama güvenlik iddiası olarak sunulmaz.

**`pg_explain` davranışı:**

- `analyze=false`: `EXPLAIN` sorguyu çalıştırmaz → read yetkisi her ifade türü için yeterli.
- `analyze=true`, read yetkisi: `BEGIN READ ONLY` içinde `EXPLAIN ANALYZE`, ardından ROLLBACK. SELECT için
  gerçek süreler döner; yazma ifadesini PG kendisi reddeder ve anlaşılır hata dönülür.
- `analyze=true`, write yetkisi: normal transaction içinde çalışır ve **her zaman ROLLBACK** edilir.
- Mevcut koddaki "EXPLAIN ANALYZE'ı korumasız çalıştırıp commit etme" hatası böylece kapanır.

`allowed_schemas` yalnız keşif tool'larını süzer; serbest SQL'i kısıtlamaz. Bu sınır tool açıklamasında ve
dokümantasyonda açıkça yazılır.

### 6.3 Prometheus

Prometheus HTTP API'sini kullanır; Mimir, Thanos ve VictoriaMetrics ile uyumludur.

| Tool | Açıklama |
|---|---|
| `prom_query(promql, time?)` | Anlık sorgu |
| `prom_query_range(promql, start, end, step?)` | `step` verilmezse ~120 nokta hedeflenir. Seri başına özet (min/max/ort/son) + örneklenmiş noktalar |
| `prom_list_metrics(match?)` | Metrik adı, türü, help (`/api/v1/metadata` + `label/__name__/values`) |
| `prom_label_values(label, match?)` | Label değerleri |
| `prom_alerts()` | Aktif alarmlar ve kural grubu durumu |

### 6.4 Loki

| Tool | Açıklama |
|---|---|
| `loki_query(logql, start?, end?, limit?, direction?)` | Log sorgusu veya LogQL metrik sorgusu; sonuç türüne göre formatlanır |
| `loki_labels(start?, end?)` | Label adları |
| `loki_label_values(label, start?, end?)` | Label değerleri |

### 6.5 Ortak kurallar

- Zaman: RFC3339 veya göreli (`now`, `now-15m`, `now-2h`). Varsayılan aralık: son 1 saat.
- Varsayılan limitler (bağlantı başına değiştirilebilir): PG 500 satır; Prometheus 100 seri;
  Loki 500 satır, satır başına 2 KB, en çok 24 saat aralık; her yanıt en çok 64 KB metin.
- Kırpma her zaman açıkça belirtilir ("312/5000 satır gösteriliyor — WHERE/LIMIT ile daraltın").
- Hata mesajları backend hatasını iletir ama DSN, header veya iç host bilgisi sızdırmaz.

## 7. State deposu

`Store` arayüzü; tek implementasyon SQLite (aiosqlite, WAL, `synchronous=NORMAL`, tek yazıcı bağlantı).
Tablolar: `clients`, `pending_authorizations`, `auth_codes`, `tokens` (hash, aile id, tür, subject, gruplar,
son kullanma, iptal), `upstream_sessions` (şifreli), `rate_limits`, `audit_events`. Şema sürümü
`schema_version` tablosunda; açılışta sıralı migration'lar uygulanır.

Performans: tool başına bir audit satırı ve arada bir token işlemi. Audit yazmaları kuyruğa alınır ve
toplu yazılır (her 1 sn veya 100 olay); tool yanıtı audit yazmasını beklemez. Kapanışta kuyruk boşaltılır.
Süresi dolmuş kod/token/pending kayıtları saatte bir temizlenir. Audit saklama süresi config'le
(varsayılan 90 gün).

Bilinen sınır: tek replika. Birden fazla replika gerektiğinde `Store`'a PostgreSQL implementasyonu eklenir.

## 8. Gözlemlenebilirlik

- **Log:** stdout'a JSON. Alanlar: `ts`, `level`, `logger`, `msg`, `request_id`, `subject`, `connection`.
  Audit olayları `event: audit` ile aynı akışa da yazılır (Loki'ye toplanabilir).
- **Metrikler** (`metrics_port`, `/metrics`): `tool_calls_total{tool,connection,result}`,
  `tool_duration_seconds{tool,connection}`, `backend_up{connection}`, `auth_events_total{event}`.
- **Sağlık:** `/healthz` (süreç ayakta), `/readyz` (state store yazılabilir; backend'ler dahil değil).

## 9. Paketleme ve dağıtım

- **Dockerfile:** multi-stage, `uv`, `python:3.12-slim`, uid 10001, yazılabilir yalnız `/data`, `HEALTHCHECK`.
  Salt okunur kök dosya sistemiyle çalışabilir.
- **CI (GitHub Actions):** ruff, mypy strict, unit + integration testleri, imaj build, Trivy taraması;
  tag'de GHCR'a amd64+arm64, SBOM ve provenance ile push.
- **`compose.yml`:** `<pkg>` + Caddy (Let's Encrypt). Kullanıcı domain'i, config'i ve `.env`'i verir.
- **`compose.dev.yml`:** örnek verili PostgreSQL, Prometheus, Loki ve log üreten küçük bir servis;
  integration testleri ve yerel deneme bunu kullanır.
- `railway.json` kaldırılır; Dockerfile her konteyner platformunda çalışır.

## 10. Test stratejisi

- **Unit:** config yükleme ve interpolasyon (tanımsız değişken hatası dahil), yetki matrisi
  (grant × mode × grup kombinasyonları), token yaşam döngüsü (süre dolumu, rotasyon, reuse detection,
  revoke), rate-limit, zaman ayrıştırma, limit/kırpma, Prometheus özetleme, log maskeleme.
- **Integration (testcontainers):**
  - PostgreSQL: read modda şunların hepsinin reddedildiği — `COMMIT; DELETE ...`,
    `WITH x AS (DELETE ...) SELECT`, `nextval()`, yazma yapan
    fonksiyon çağrısı, `SELECT ... FOR UPDATE` dahil kilit alan ifadeler, DML üzerinde
    `EXPLAIN ANALYZE`; write modda `pg_explain(analyze=true)` sonrası verinin değişmediği; transaction
    rollback; statement timeout.
  - Prometheus ve Loki: örnek veri üzerinde sorgular, limit ve kırpma, tenant header'ı.
- **Uçtan uca OAuth:** Test istemcisi DCR → authorize → token → tool çağrısı → refresh → revoke yürütür.
  OIDC için sahte issuer (yerel JWKS). Authentik için manuel kontrol listesi (`docs/authentik.md`).
- **Güvenlik:** izinsiz redirect_uri ile kayıt reddi, PKCE'siz authorize reddi, CSRF'siz login reddi,
  token'sız isteğe 401, yetkisiz kullanıcıya bağlantının "not found" görünmesi, log'larda secret olmaması.

## 11. Dokümantasyon

README (hızlı başlangıç: compose + local mod), `docs/configuration.md` (tam referans),
`docs/authentik.md`, `docs/postgres-roles.md` (bağlantı başına kısıtlı rol tarifi),
`docs/connectors.md` (claude.ai / Desktop / Code), `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`MIGRATION.md` (0.1 → 1.0), repo `CLAUDE.md` (convention'lar, test komutları).

## 12. Aşamalar

Her aşama kendi uygulama planına sahip olur ve kendi başına çalışır durumda biter.

1. **Çekirdek + çoklu PostgreSQL + auth:** yeniden adlandırma, config, state store, OAuth AS, local ve
   OIDC kimlik, policy, audit, PG backend'i ve 9 PG tool'u, ortak tool'lar, temel Dockerfile.
   Mevcut tek-DB kurulumu bu aşamanın sonunda yeni config ile çalışır.
2. **Prometheus backend'i:** client, 5 tool, özetleme, integration testleri.
3. **Loki backend'i:** client, 3 tool, integration testleri.
4. **Paketleme ve open-source hijyeni:** compose dosyaları + Caddy, CI/GHCR, metrikler, dokümantasyon seti.

## 13. Açık kararlar

- Proje adı (Bölüm 2).
