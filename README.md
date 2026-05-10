# blastrad

**CI/CD Pipeline Attack Path Analyzer**

blastrad, GitLab CI/CD pipeline'larını güvenlik açısından analiz eden bir komut satırı aracıdır. Mevcut araçların yaptığı gibi statik kural kontrolü yapmak yerine, pipeline'ı bir **güvenlik grafı** olarak modelleyerek untrusted kaynaklardan (fork MR, external trigger) kritik hedeflere (production secret, korumasız environment) giden **saldırı yollarını** ve her bulgunun **blast radius'unu** hesaplar.

```
[CRITICAL] Privilege Escalation: merge_request_event → deploy-production → K8S_TOKEN
──────────────────────────────────────────────────────────────────────────────────────
  Path:         merge_request_event → deploy-production → K8S_TOKEN
  Blast Radius: 3 kritik kaynak
  Açıklama:     Untrusted kaynak 'merge_request_event', 2 adımda kritik kaynak
                'K8S_TOKEN' üzerine erişim sağlayabilir.

[HIGH] Production job shared runner üzerinde çalışıyor
──────────────────────────────────────────────────────────────────────────────────────
  Path:         deploy-production → shared-runner-01
  Blast Radius: 1 kritik kaynak
  Açıklama:     'deploy-production' job'u production'a deploy ediyor ancak shared
                runner kullanıyor. Diğer projelerin job'ları bu runner'ın cache'ine
                erişebilir.
```

---

## Neden blastrad?

Mevcut araçların ortak sorunu: hepsi **statik kural tabanlı** çalışır. "Bu pattern kötüdür" derler ama **neden kötü, ne olur, ne kadar ileri gidilebilir** sorusunu cevaplamaz.

| Araç | Ne Yapar | Eksik |
|---|---|---|
| Checkov | YAML rule check | Context yok, ilişki analizi yok |
| gitleaks | Secret tarama | Sadece secret, erişilebilirlik analizi yok |
| zizmor | GitHub Actions linter | Sadece GitHub, GitLab desteği yok |
| Semgrep | Pattern matching | Pipeline'a özel değil |
| **blastrad** | **Graf tabanlı path analizi** | — |

blastrad'ın farkı: `fork MR` açan bir saldırganın `K8S_TOKEN`'a kaç adımda ulaşabileceğini, hangi job'ları geçeceğini ve oradan ne kadar hasar verebileceğini **somut olarak** göstermesi.

---

## Nasıl Çalışır

Pipeline üç aşamada analiz edilir:

**1. Veri Toplama**

`.gitlab-ci.yml` dosyası parse edilerek job tanımları, trigger koşulları, bağımlılıklar ve environment bilgileri çıkarılır. GitLab API üzerinden variable'ların `protected`/`masked` durumu, environment'ların koruma ayarları ve runner konfigürasyonu tamamlanır.

**2. Graf Modelleme**

Toplanan veri bir yönlü grafa dönüştürülür:

```
Node tipleri:  Trigger | Job | Secret | Environment | Runner
Edge tipleri:  triggers | reads_secret | deploys_to | runs_on | depends_on

Örnek:
  [fork_mr] ──triggers──▶ [deploy-prod] ──reads_secret──▶ [K8S_TOKEN]
                                 │
                           ──deploys_to──▶ [production env]
                                 │
                           ──runs_on──▶ [shared-runner-01]
```

**3. Analiz**

Graf üzerinde iki analiz çalışır:

- **Privilege Escalation Path Finding:** Her untrusted trigger node'undan DFS başlatılır. Kritik bir hedefe (protected=false secret, korumasız production environment) ulaşan tüm yollar bulgu olarak raporlanır.
- **Blast Radius Hesaplama:** Bulunan her path için, hedef node'dan ulaşılabilecek toplam kritik kaynak sayısı hesaplanır.

---

## Kurulum

### Binary (Önerilen)

```bash
# Linux / macOS
curl -L https://github.com/karakoc49/blastrad/releases/latest/download/blastrad_linux_amd64 -o blastrad
chmod +x blastrad

# Windows
# Releases sayfasından blastrad_windows_amd64.exe indir
```

### Kaynak Koddan

```bash
git clone https://github.com/karakoc49/blastrad
cd blastrad
go build -o blastrad .
```

Go 1.22+ gerektirir.

---

## Kullanım

### GitLab Token Oluşturma

GitLab → Settings → Access Tokens → `read_api` scope ile token oluştur.

### Temel Kullanım

```bash
blastrad scan --token glpat-xxxx --project mygroup/myproject
```

### Self-Hosted GitLab

```bash
blastrad scan \
  --token glpat-xxxx \
  --project 42 \
  --url https://gitlab.sirketim.com
```

### Farklı CI Dosyası

```bash
blastrad scan \
  --token glpat-xxxx \
  --project mygroup/myproject \
  --file ci/production.yml
```

### Tüm Flag'ler

| Flag | Kısa | Varsayılan | Açıklama |
|---|---|---|---|
| `--token` | `-t` | — | GitLab Access Token **(zorunlu)** |
| `--project` | `-p` | — | Proje ID veya `namespace/proje` **(zorunlu)** |
| `--url` | `-u` | `https://gitlab.com` | GitLab instance URL |
| `--file` | `-f` | `.gitlab-ci.yml` | CI dosyası yolu |

### CI/CD Entegrasyonu

blastrad, kritik veya yüksek bulgu varsa `exit code 1` döndürür. Bu davranış pipeline entegrasyonunda kullanışlıdır:

```yaml
# .gitlab-ci.yml
security-scan:
  stage: security
  image: golang:1.22
  script:
    - go install github.com/karakoc49/blastrad@latest
    - blastrad scan --token $BLASTRAD_TOKEN --project $CI_PROJECT_PATH
  allow_failure: false  # Kritik bulgu varsa pipeline durur
```

---

## Tespit Edilen Bulgular

### Privilege Escalation Path

Untrusted bir kaynaktan (fork açan herhangi biri) kritik bir hedefe ulaşan yol.

**Örnek senaryo:**

```yaml
deploy-prod:
  environment: production
  variables:
    K8S_TOKEN: $KUBE_SECRET   # protected=false
  rules:
    - if: '$CI_MERGE_REQUEST_IID'  # fork MR da tetikleyebilir
```

blastrad bu konfigürasyonda şunu tespit eder: fork açan herhangi biri `deploy-prod` job'unu tetikleyebilir ve bu job `K8S_TOKEN`'a erişebilir.

**Severity:** Variable'ın `protected`/`masked` durumuna göre CRITICAL veya HIGH.

### Shared Runner ile Production Deploy

Production environment'a deploy eden bir job'un, başka projelerle paylaşılan bir runner üzerinde çalışması.

**Risk:** Shared runner'da çalışan başka projelerin job'ları bu runner'ın geçici dosyalarına, cache'ine ve bazı durumlarda environment variable'larına erişebilir.

**Severity:** HIGH

---

## Mimari

```
blastrad/
├── main.go
├── cmd/
│   ├── root.go          # Cobra root komutu
│   └── scan.go          # "blastrad scan" alt komutu ve flag tanımları
├── collector/
│   ├── parser/          # .gitlab-ci.yml okuma ve parse
│   │   ├── types.go     # Pipeline, Job, Rule, Environment struct'ları
│   │   └── parser.go    # İki aşamalı YAML parse mantığı
│   └── gitlab/          # GitLab REST API istemcisi
│       ├── types.go     # API response struct'ları
│       ├── client.go    # HTTP katmanı, pagination
│       └── fetcher.go   # Variable, environment, runner veri toplama
├── graph/
│   ├── node.go          # Node/Edge tipleri, trust ve criticality modeli
│   ├── graph.go         # Adjacency list graf implementasyonu
│   ├── builder.go       # Parser + API verisini grafa dönüştürme
│   └── analyzer.go      # DFS path finding, blast radius hesaplama
└── reporter/
    └── terminal.go      # Renkli terminal çıktısı, deduplication
```

---

## Geliştirme

```bash
# Tüm testleri çalıştır
go test ./...

# Belirli bir paketi verbose çalıştır
go test ./graph/... -v

# Derleme
go build -o blastrad .
```

### Yeni Kural Eklemek

Yeni bir güvenlik kuralı eklemek için `graph/analyzer.go` dosyasına yeni bir `find*` fonksiyonu yaz ve `Analyze()` içinden çağır:

```go
func (a *Analyzer) Analyze() []Finding {
    var findings []Finding
    findings = append(findings, a.findPrivEscPaths()...)
    findings = append(findings, a.findSharedRunnerRisks()...)
    findings = append(findings, a.findYeniKural()...)  // ← buraya ekle
    return findings
}
```

---

## Yol Haritası

- [ ] SARIF output (GitLab/GitHub Security Dashboard entegrasyonu)
- [ ] GitHub Actions desteği
- [ ] JSON output formatı
- [ ] `--only-critical` flag ile filtreleme
- [ ] Unprotected variable tespiti (masked=false olanlar)
- [ ] Cross-pipeline bağımlılık analizi

---

## Lisans

MIT

---

*blastrad, Go ile yazılmış bağımsız bir güvenlik aracıdır. GitLab Inc. ile herhangi bir bağlantısı yoktur.*