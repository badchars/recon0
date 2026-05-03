# recon0 panel — feature plan

Living document. Yeni feature'lar buraya eklenir, durumları güncellenir.

---

## Principles (her zaman uygula)

- **Don't complicate.** En basit çalışan hal. Üç satır > akıllı abstraction.
- **SOLID + best practice.** Tek sorumluluk, açık-kapalı, küçük interface.
- **Yok'u savun.** Login, register, multi-user, fancy UI animasyonu, RBAC, audit log → **YOK**. İhtiyaç olunca tartışırız.
- **No premature abstraction.** İki feature aynı pattern'i kullanmadan ortak helper yazma.
- **No defensive code where unneeded.** Internal sınırlarda input validate etme. Sadece user input + external API'de.
- **Storage:** programs ve scan verisi recon0'da JSON. Panel'in kendi durumu (vulnerabilities, settings) localStorage. **Yeni DB yok.**
- **Backend değişikliği**: küçük, izole, mevcut handler pattern'ini takip et.
- **Frontend değişikliği**: shadcn/ui zaten kurulu, yeni paket eklemeden çöz.

---

## Storage map

**Kural:** Project data (kalıcı, başka makineden de görülmesi gereken) → recon0 JSON dosyaları. Sadece UI preference (bir cihaz/tarayıcıya ait) → panel localStorage.

Tüm recon0 dosyaları `cfg.OutputDir` (default `runs/`) altında. Panel data dosyaları scan job dir'larıyla aynı kökte kardeş — ayrı path config'i yok.

```
runs/
├── queue.json                  # mevcut
├── programs.json               # F1
├── host-annotations.json       # F4
├── vulnerabilities.json        # F2
├── vuln-attachments/           # F8
│   └── <vuln-id>/...
└── <job-id>/                   # mevcut, scan dirs
    ├── state.json
    └── work/...
```

| Veri | Yol | Format |
|------|-----|--------|
| Programs | `runs/programs.json` | array, mutex'li |
| Host annotations | `runs/host-annotations.json` | hostname → annotation map |
| Vulnerabilities | `runs/vulnerabilities.json` | array, id'li |
| Vuln attachments | `runs/vuln-attachments/<vuln-id>/...` | dosya sistemi |
| Scan state | `runs/<id>/state.json` | mevcut, değişmez |
| Scan output | `runs/<id>/output/...` | mevcut, değişmez |
| Panel UI prefs | localStorage | Zustand persist |

**recon0 storage pattern (her resource için aynı):** `internal/<name>/<name>.go` paketi mutex'li JSON read/write yapar. ~80-100 satır per resource. CRUD endpoint'leri `internal/api/api.go`'da pattern eşit.

---

## Cross-cutting concerns (her yeni paket bunlara uy)

Yeni resource paketleri (`programs`, `vulnerabilities`, `host-annotations`) için ortak standartlar. Tek tek feature'larda tekrar yazılmaz, buradan referansla.

### ID şemaları

| Resource | ID şeması | Immutable? | Örnek |
|----------|-----------|------------|-------|
| Program | `name` (slug, kullanıcı seçer) | **Evet** — PUT'ta `name` değiştirilemez, sadece description/vendor/scope düzenlenir | `income-sg` |
| Vulnerability | `v-YYYYMMDD-NNN` (server üretir) | **Evet** | `v-20260502-001` |
| Host annotation | `hostname` (normalize edilmiş) | **Evet** | `api.income.com.sg` |

### Schema standardı

Her resource bu üç alanı tutar:
```ts
{
  created_at: string;   // RFC3339 UTC, server set
  updated_at: string;   // RFC3339 UTC, server set on every write
  version: number;      // monotonic counter, server increments on each write
}
```

`version` optimistic concurrency için. PUT body'sinde `expected_version` gönderilir; mismatch olursa 409 + son state döner. Panel "veri değişti, reload?" diyalogu açar.

### Atomic write + error propagation

Tüm yeni paketler şu pattern'i kullanır:

```go
func (s *Store) save() error {
    data, err := json.MarshalIndent(s.items, "", "  ")
    if err != nil { return fmt.Errorf("marshal: %w", err) }
    if err := os.MkdirAll(filepath.Dir(s.file), 0755); err != nil { return err }
    tmp := s.file + ".tmp"
    if err := os.WriteFile(tmp, data, 0644); err != nil { return fmt.Errorf("write tmp: %w", err) }
    if err := os.Rename(tmp, s.file); err != nil { return fmt.Errorf("rename: %w", err) }
    return nil
}
```

**Hata yutulmaz.** Caller (handler) error'ı `writeError(w, 500, ...)` ile döndürür. Panel kullanıcıya gösterir.

> Mevcut `queue.go:save()` sessizce yutuyor — ayrı bir bug fix task'ı.

### Error response

Tüm yeni handler'lar JSON error döndürür:
```go
func writeError(w http.ResponseWriter, status int, msg string) {
    writeJSON(w, status, map[string]string{"error": msg})
}
```
Mevcut `http.Error(w, "...", 400)` çağrıları (plain text) kalsın — backwards compatible. Yeni handler'lar `writeError`. Sonra hepsi convert edilebilir, ama acil değil.

### URL stili

- Collection plural: `/api/programs`, `/api/vulnerabilities`, `/api/host-annotations`
- Single item: `/api/<collection>/<id>`
- Sub-resource: `/api/<collection>/<id>/<subname>` (örn `/api/runs/<id>/hosts`)
- Lowercase + hyphen separated. snake_case yok.

---

## Features

### F1. Programs (CRUD + scope)

**Status:** planned

**Amaç:** HackerOne / Bugcrowd / YesWeHack programlarını tanımlamak. Her program: ad, açıklama, vendor, vendor link, scope (asset listesi).

**Veri modeli (`runs/programs.json`):**
```json
[
  {
    "name": "income-sg",
    "description": "Singapore insurance",
    "vendor": "hackerone",
    "vendor_link": "https://hackerone.com/income",
    "scope": ["*.income.com.sg", "api.income.com.sg"],
    "created_at": "...",
    "updated_at": "...",
    "version": 1
  }
]
```

**recon0 değişiklik:**
- Yeni paket: `internal/programs/programs.go` — JSON file mutex'li read/write, ~100 satır. Atomic write + error propagation pattern'i (cross-cutting concerns).
- Yeni handler'lar (`internal/api/api.go`):
  - `GET /api/programs`
  - `GET /api/programs/:name`
  - `POST /api/programs`
  - `PUT /api/programs/:name`
  - `DELETE /api/programs/:name`
- Mevcut handler pattern'ini takip et + cross-cutting `writeError` helper'ı kullan.
- Validation: `name` non-empty + slug regex (`^[a-z0-9][a-z0-9-]{0,62}$`). Vendor enum check yok, free string. Vendor link URL regex yok, free string.
- **`name` immutable** — PUT body'sinde `name` field'ı görmezden gelinir, URL'deki `:name` authoritative.
- PUT body'sinde `expected_version` zorunlu — mismatch'te 409.

**Panel değişiklik:**
- Sidebar: "Programs" menüsü (Vulnerabilities'in üstünde)
- Yeni sayfa: `/programs` → liste tablosu + `[+ New Program]`
- Yeni sayfa: `/programs/[name]` → edit form (delete butonu dahil)
- Form alanları: name (slug), description (textarea), vendor (free text + datalist suggest: hackerone, bugcrowd, yeswehack, intigriti, private), vendor_link (url), scope (textarea, satır başına asset)
- API hooks: `usePrograms`, `useProgram`, `useCreateProgram`, `useUpdateProgram`, `useDeleteProgram`

**Loose coupling:** Run, free-text `program` ile çalışmaya devam eder. Program kayıtlı olmasa bile run başlar. Panel'de program kayıtlı değilse "register this program" linki gösterilir (lazy approach).

---

### F2. Vulnerability ↔ Program/Asset bağlantısı

**Status:** planned

**Amaç:** Vuln kaydı bir program'a ait olur, asset o programın `scope`'undan seçilir. Free text karmaşası biter. Storage **localStorage'dan recon0 JSON dosyasına taşınır** — vulnerabilities project data'dır.

**recon0 değişiklik:**
- Yeni paket: `internal/vulnerabilities/vulnerabilities.go` — JSON file mutex'li, ~120 satır. Atomic write + error propagation (cross-cutting).
- Storage: `runs/vulnerabilities.json` (array of vuln objects, id'li)
- ID şeması: `v-YYYYMMDD-NNN` (server üretir; her gün için NNN sıfırlanır, yeni kayıt counter'ı arttırır). Cross-cutting'e bak.
- `created_at`, `updated_at`, `version` (cross-cutting schema standardı).
- Endpoint'ler:
  ```
  GET    /api/vulnerabilities              → liste
  GET    /api/vulnerabilities/:id          → tek
  POST   /api/vulnerabilities              → oluştur (id server üretir)
  PUT    /api/vulnerabilities/:id          → güncelle (body'de expected_version zorunlu, mismatch → 409)
  DELETE /api/vulnerabilities/:id          → sil
  ```

**Panel değişiklik:**
- `lib/store/vulnerabilities.ts` localStorage'dan **kaldırılır**, yerine `lib/api/recon0.ts`'e vulnerability fetcher'ları + TanStack Query hook'ları (`useVulnerabilities`, `useVulnerability`, `useCreateVuln`, `useUpdateVuln`, `useDeleteVuln`)
- **Migration helper** (panel'de tek seferlik): localStorage'da eski vuln'lar varsa, panel ilk açılışta `POST /api/vulnerabilities`'e bir bir gönderir, başarılıysa localStorage temizler. Settings'te "Migrate from localStorage" butonu da var (manuel tetikleme).
- Vuln editör'ünde: program select (Programs API'den), asset select (seçili programın `scope`'undan dropdown + "custom" inline input fallback)
- Vulnerabilities list: program filter, program kolonu, vendor rozeti renk kodlu (hackerone gri, bugcrowd turuncu vs. — basit)

**Önemli:** asset için dropdown ama yine de free-text fallback (scope listede olmayan custom asset için). Rare case ama lock'lamayalım.

---

### F3. Run Detail — output viewer tab'ları

**Status:** planned

**Amaç:** Scan biten run'ın çıktılarını UI'da göstermek. Şu an sadece pipeline progress + log var; finding/host/endpoint görünmüyor.

**recon0 değişiklik (sadece dosya passthrough handler'lar — file → JSON):**
```
GET /api/runs/:id/hosts          → work/raw/httpx.hosts.txt.json (JSONL)
GET /api/runs/:id/findings       → work/output/findings.json (JSONL)
GET /api/runs/:id/investigations → work/output/investigations.json (JSON array)
GET /api/runs/:id/endpoints      → work/output/endpoints.json (JSONL)
GET /api/runs/:id/attack-surface → work/output/attack-surface.json
GET /api/runs/:id/smartfuzz      → work/raw/smartfuzz.findings.json (JSONL)
```
Her handler ~10 satır. Mevcut handleLogs pattern'ini takip et. Filtering/pagination yok — client tarafı yeterli (en büyük: investigations ~1.6MB).

**Panel değişiklik:**

Run Detail sayfasında yeni tab'lar:
- **Hosts** — DataTable (url, status, tech rozetleri, TLS issuer, CDN). Row click → **Host Summary Sheet** (sağdan slide):
  - Header: URL + status badge
  - Quick stats: `12 findings · 47 investigations · 89 endpoints · 3 smartfuzz`
  - Per-kategori top 3 satır
  - Footer button: **"View host details →"** → `/runs/[id]/hosts/[hostname]`
- **Findings** — severity filtreli tablo, row click → drawer detay
- **Investigations** — vuln_type + confidence filtreli tablo
- **Endpoints** — method renkli tablo, search, IDOR/SSRF aday vurgusu
- **Attack Surface** — 3 sütun kart (API / admin / exposed files)
- **Smartfuzz** — severity + template tablo

**Yeni sayfa: Host Detail** (`/runs/[id]/hosts/[hostname]`)
- Header: full URL, status, tech, TLS info, CDN, server header
- Tab'lar: Findings / Investigations / Endpoints / Smartfuzz — hepsi sadece bu host'a filtrelenmiş

**Filtreleme stratejisi:** client-side — fetch tüm JSON, hostname/URL'den match. Server-side filter eklemek backend'e ek param/query gerektirir, basit kalalım.

**Kod paylaşımı:** Run Detail tab'larındaki DataTable'lar host-filtered prop alır → Host Detail aynı component'leri filter ile kullanır. Tek implementation, iki view.

---

### F4. Host annotations (description + review status)

**Status:** planned

**Amaç:** Bir host'u manuel inceleyip incelemediğini ve aldığın notları kalıcı tutmak. Yeni run geldiğinde de aynı host'un durumu korunur.

**Veri modeli (`runs/host-annotations.json`):**
```json
{
  "api.income.com.sg": {
    "description": "Reviewed Spring actuator endpoints, no exposure",
    "review_status": "reviewed",
    "created_at": "2026-05-02T15:00:00Z",
    "updated_at": "2026-05-02T15:00:00Z",
    "version": 3
  },
  "admin.income.com.sg": {
    "description": "",
    "review_status": "reviewing",
    "created_at": "...",
    "updated_at": "...",
    "version": 1
  }
}
```

```ts
type ReviewStatus = "not_reviewed" | "reviewing" | "reviewed";
```

**Anahtar tasarım:** annotation **hostname**'e bağlı, run-id'ye değil. Aynı host birden fazla run'da görünebilir; review durumu run'lar arasında sticky olmalı.

**Hostname normalization (key kuralı):**
- Lowercase
- Port stripped: `api.income.com.sg:443` → `api.income.com.sg`
- Scheme stripped: `https://api.income.com.sg` → `api.income.com.sg`
- Trailing slash stripped
- Server normalize eder; panel ne gönderirse gönder, server canonical key ile saklar.

**recon0 değişiklik:**
- Yeni paket: `internal/annotations/annotations.go` — JSON file mutex'li, ~80 satır. Atomic write (cross-cutting).
- Endpoint'ler (URL stili plural — cross-cutting):
  ```
  GET    /api/host-annotations              → tüm map
  GET    /api/host-annotations/:hostname    → tek annotation
  PUT    /api/host-annotations/:hostname    → upsert (body: description, review_status, expected_version?)
  DELETE /api/host-annotations/:hostname    → sil
  ```
- PUT'ta `expected_version` opsiyonel (yeni kayıt için yok, mevcut için var). Yeni kayıtsa `created_at` set, version=1. Mevcutsa version artar.

**Panel değişiklik:**
- API client: `lib/api/recon0.ts`'e annotations method'ları
- Hosts tab tablosunda yeni kolon: **Review** rozeti (renkli — gri/sarı/yeşil)
- Hosts tablosunda yeni filter: review status (all / not_reviewed / reviewing / reviewed)
- Host Summary Sheet'te: review status select + description textarea (debounced PUT)
- Host Detail page header'ında aynı alanlar daha geniş

**UX:**
- Default `not_reviewed` (gri)
- Tek tıkla `reviewing` (sarı) → sen baktın, halledilmedi
- Tek tıkla `reviewed` (yeşil) → bitti
- Description boş bırakılabilir, opsiyonel
- Edit → debounced auto-save (sessiz, toast yok)

**Notlar:**
- Description'ı şimdilik plain text yap. Markdown gerekirse F4.1 olarak ayrı feature'a yükselt.
- "reviewed" host'lar varsayılan filter'da gizlensin mi? — opsiyon, default off, settings'te toggle.

---

### F5. Vulnerability schema refinements

**Status:** planned

**Amaç:** Bug bounty workflow'una uygun hale getirmek. Description ve PoC ayrı markdown editör'lerinin tek alana birleşmesi + submission lifecycle + bounty tracking.

**Schema değişikliği (recon0 vulnerabilities.json — F2 ile birlikte):**

Mevcut (localStorage'da):
```ts
{
  description: string;   // markdown
  poc: string;           // markdown — KALDIRILACAK
  status: VulnStatus;    // open|triaged|fixed|duplicate|false_positive|wont_fix — REPLACE
}
```

Yeni:
```ts
{
  description: string;            // tek markdown alanı (Description + PoC kullanıcı kendi başlıklarıyla)
  submission_status: SubmissionStatus;  // YENİ — replaces "status"
  bounty: number;                 // YENİ — kazanılan tutar (USD, 0 = henüz yok)
}

type SubmissionStatus =
  | "wait"        // submit edilmedi / triajda
  | "submitted"   // raporu yolladım, henüz yanıt yok
  | "triaged"     // platform geçerli kabul etti
  | "na"          // not applicable, reddedildi
  | "duplicate";  // duplicate olarak kapatıldı
```

**Default:** `submission_status: "wait"`, `bounty: 0`.

**recon0 değişiklik:** schema F2'deki `internal/vulnerabilities/vulnerabilities.go`'da bu alanlarla doğar. Ayrı paket gerekmez — F2 ile aynı pakette.

**Panel değişiklik:**
- `vuln-form.tsx` — tek markdown editör (yükseklik artar, ~500px), submission_status select, bounty numeric input ($ prefix)
- `vulns-table.tsx` — Status kolonu submission_status rozetlerini gösterir (renkler: wait=gray, submitted=blue, triaged=amber, na=muted, duplicate=muted), yeni Bounty kolonu (`$1,500` formatlı, 0 ise dash)
- Filter dropdown'ı eski status değerleri yerine submission_status'lar
- Vuln detail/edit'te bounty alanı: 0'sa "no bounty yet" placeholder, > 0 ise prominent göster

**Migration:** F2'nin localStorage→recon0 migration'ı sırasında her vuln için: `submission_status` yoksa `wait` ata, `poc` doluysa description'a append et (`\n\n## Proof of Concept\n\n` prefix), `poc` field'ı drop. Tek seferlik, sessiz.

---

### F6. Cross-tab pivots — clickable hostname/URL

**Status:** planned

**Amaç:** Findings, Investigations, Endpoints, Smartfuzz tab'larında hostname/URL gördüğünde tek tıkla ilgili Host Detail page'e gitmek. Şu an manuel arama gerekir.

**recon0 değişiklik:** YOK.

**Panel değişiklik:**
- Yeni component: `<HostLink hostname="..." runId="..." />` — pure Link, route'a yönlendirir
- Findings/Investigations/Endpoints/Smartfuzz tablo satırlarında URL/host kolonu artık raw string değil `HostLink`
- Vulnerabilities list'te asset kolonu da: vuln'ın `source_run_id` varsa o run'daki Host Detail'a, yoksa vuln editör'üne

**Etki:** ~30 satır kod, navigasyon dramatic improve.

---

### F7. Vulnerability export — copy as markdown

**Status:** planned

**Amaç:** Vuln'ı HackerOne / Bugcrowd / YesWeHack rapor formuna kopyala-yapıştır için tek-tıkla temiz markdown üret.

**Format:**
```markdown
## [<SEVERITY>] <Title>

**Asset:** <asset>
**Program:** <program> (<vendor>)

### Description

<description markdown — olduğu gibi>

### References
- <each reference url>
```

**recon0 değişiklik:** YOK — tamamen client-side string template.

**Panel değişiklik:**
- Vuln detail/edit page'de `[Copy as Markdown]` butonu, navigator.clipboard.writeText
- Toast: "Copied! Paste into your bounty report"
- Bonus: dropdown ile "Copy as plain text" / "Copy as HTML" varyantları (sonraya)

---

### F8. Screenshot upload in vulnerability editor

**Status:** planned

**Amaç:** Vuln description'a ekran görüntüsü eklemek. Bug bounty raporlarında PoC görseli olmadan dürüst inceleme yok.

**Storage stratejisi:** recon0 disk'inde, vuln'a bağlı. Markdown'da göreli URL referansı.

**Disk layout:**
```
runs/vuln-attachments/
  └─ <vuln-id>/
       ├─ 2026-05-02T14-30-burp-response.png
       └─ 2026-05-02T14-31-payload.png
```

**Markdown'daki referans:**
```markdown
![Burp response](/api/vulnerabilities/v-abc123/attachments/2026-05-02T14-30-burp-response.png)
```

**recon0 değişiklik:**
- `internal/vulnerabilities/vulnerabilities.go`'a attachment helper'ları ekle (~50 satır):
  - `SaveAttachment(vulnID, filename, reader) (storedName string, err error)` — sanitize + write
  - `GetAttachment(vulnID, filename) (path string, err error)` — read path
  - `DeleteAttachment(vulnID, filename) error`
  - Vuln silindiğinde dizini sil (mevcut `Delete()`'e eklenir)
- Endpoint'ler (`internal/api/api.go`):
  ```
  POST   /api/vulnerabilities/:id/attachments         # multipart, max 10MB
  GET    /api/vulnerabilities/:id/attachments/:name   # serve file
  DELETE /api/vulnerabilities/:id/attachments/:name
  ```
- Validation (server-side):
  - Max 10MB per file
  - MIME type beyaz liste: `image/png`, `image/jpeg`, `image/webp`, `image/gif`
  - Filename sanitize: sadece `[a-zA-Z0-9-_.]`, path separator yok, server-side timestamp prefix ekle
- Static serving: standard `http.ServeFile`, doğru `Content-Type` header

**Panel değişiklik:**
- Vuln editör'ündeki markdown editörüne `onPaste` handler:
  - Pano içeriğinde image var mı kontrol et
  - Var → recon0'a `POST .../attachments` (multipart)
  - Yanıttan dönen URL'i markdown'a `![pasted-screenshot](URL)` formatında cursor'a inject
- `onDrop` handler aynı mantık (drag-drop dosya)
- "Add image" toolbar butonu → file picker (alternatif)
- Kullanıcı işaret edip silebilsin (ileride): markdown'dan görsel referansı silindiğinde orphan dosya kalır → şimdilik temizlik vuln silinince yapılır, ortadan görsel temizliği MVP'de yok

**UX akışı (en önemli):**
```
1. macOS Cmd+Shift+4 → ekran görüntüsü panoya
2. Vuln editöründe Cmd+V
3. Editör otomatik upload + markdown insert
4. Preview'da görsel hemen render
```

GitHub PR yorum kutusu pattern'i. Bu olmazsa ekran görüntüsü eklemek angarya olur.

---

### F9. Cancel running scan

**Status:** planned

**Amaç:** Run Detail sayfasındaki "Cancel" butonu şu an disabled — running scan'i durdurma yolu yok. Yanlış parametrelerle başlatılan veya 6 saatlik takılı kalmış scan'i sonlandırabilmek için gerekli.

**recon0 değişiklik:**
- Yeni endpoint: `POST /api/runs/:id/cancel`
- Aktif run değilse 400; aktif değil veya `:id` eşleşmiyorsa 404
- Pipeline'a context cancel sinyali gönderir. Mevcut `signal.Notify(SIGINT)` handler'ı zaten `cancel()` çağırıyor (`cmd/recon0/main.go:229-235`) — aynı `cancelFn`'i state üzerinden API'ye expose et.
- Subprocess'ler (`exec.CommandContext`) zaten context'e bağlı → context cancel olunca SIGTERM alırlar. Yeni mekanizma gerekmez.
- State `status: cancelled` olarak biter; queue job da `cancelled` işaretlenir.

**Panel değişiklik:**
- `Cancel` butonu enable (Run Detail header'ında, status=running iken).
- Click → confirm dialog → `POST /api/runs/:id/cancel`.
- Toast: "Scan cancelled".

**Edge case:** cancel sırasında stage `done` olmuş veya pipeline çoktan başka stage'e geçmişse cancel hâlâ overall durumu değiştirir. Pipeline döngüsü bir sonraki iterasyonda `ctx.Err()` görüp çıkar.

---

### F10. (placeholder) Sıradaki feature

Buraya yazacaksın, ne istediğini açıkla.

---

## Çalışma sırası (öneri)

1. **F3 backend** — 6 passthrough endpoint (her biri ~10 satır)
2. **F3 frontend** — Hosts tab + Sheet + Host Detail page (en yüksek değer; biten scan görünür hale gelir)
3. **F4** — Host annotations (description + review status); F3 frontend'le iç içe geçer, mantıklı
4. F3 diğer tab'lar (Findings, Investigations, Endpoints, Attack Surface, Smartfuzz)
5. **F9** — Cancel running scan; küçük (1 endpoint + 1 buton), F3 ile birlikte UX olarak yer almış olur
6. **F1 backend** — programs paket + 5 endpoint
7. **F1 frontend** — Programs sayfaları
8. **F2** — Vuln editör'ü programs/scope ile besle, Findings/Investigations'tan "Promote to Vuln" butonu
9. **F5** — Vuln schema refinements (description+poc → tek md, submission_status, bounty); F2 ile birlikte yapılırsa migration tek seferde olur
10. **F8** — Screenshot upload (F2 backend'inin attachment endpoint'leri); F2/F5 ile birlikte yapılması mantıklı, vuln editör'ü zaten dokunuluyor
11. **F6** — Cross-tab pivots (her tabloya HostLink); küçük, sona bırakılabilir
12. **F7** — Vuln export to markdown; küçük, sona bırakılabilir

Her feature küçük, test edilebilir, geri alınabilir kalmalı.
