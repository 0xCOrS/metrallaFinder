# RECON - (Almost) Passive Recon & Subdomain Enumeration Tool

**Author:** 0xCOrS (with a little help from Claude)  
**Language:** Python 3.9+  
**Type:** Almost passive reconnaissance (until optional screenshot phase)

_As usual, expect some spanglish_

A fast, aggressive and almost completely passive reconnaissance tool for bug bounty hunters and red teamers.  
One single command → thousands of subdomains + historical URLs + juicy files + live checks + screenshots.

If the Recon MUST be 100% passive, comment 916 & 917 lines of metrallaFinder.py

## Features

- 100 % passive until the optional screenshot phase
- Subdomain enumeration from:
  - Wayback Machine (CDX API)
  - Common Crawl (latest index)
  - crt.sh (Certificate Transparency logs)
  - Shodan domain view
- Historical URLs saved and grouped by subdomain
- Automatic hunting of 18 sensitive file extensions (`.js`, `.json`, `.pdf`, `.php`, `.bak`, `.zip`, `.sql`, databases, backups…)
- Live subdomain checking (HTTP + HTTPS) via httpstatus.io bulk API → no direct connections to target
- Single-run screenshot of every alive subdomain using **gowitness**
- Clean output structure + detailed execution log

## Output directory structure

```text
example.com/
├── subs/
│   ├── all-subs.txt
│   ├── wa-subs.txt
│   ├── cc-subs.txt
│   ├── sh-subs.txt
│   ├── crt-subs.txt
│   └── asn_info.txt
├── urls/                  → Wayback Machine URLs (one file per subdomain)
├── urlsCC/                → Common Crawl URLs (one file per subdomain)
├── urls200/               → (optional) only 200-response URLs
├── status_check/
│   ├── active_http_subdomains.txt
│   └── active_https_subdomains.txt
├── screenshots/           → gowitness screenshots + index.html + CSV report
├── <extension>_files/              → URLs pointing to .<extension> files
└── bbhunting.log          → complete execution log
```

Folders for file extensions are created only when results exist.

## Installation
```bash
pip install -r requirements.txt

# Install gowitness (required for screenshots)
go install github.com/sensepost/gowitness@latest
```

## Usage
```bash
python3 metrallaFinder.py example.com
```

## Flow

```mermaid
graph TD
    A["Inicio: python metrallaFinder.py dominio.com"] --> H["PASO 1: Información ASN"]
    H --> K["GET → ipinfo.io/IP/json"]
    K --> L["Guardar → subs/asn_info.txt"]

    L --> N["PASO 2: Recolección de Subdominios"]

    subgraph FuentesSubdominios ["Subdominios"]
        direction TB
        N --> P1["Wayback Machine"]
        P1 --> Q1["GET → web.archive.org/cdx/search/cdx<br/>?url=*.dominio.com/*&output=text&fl=original"]
        Q1 --> R1["→ urls/ + wa-subs.txt"]

        N --> P2["Common Crawl"]
        P2 --> Q2["GET → index.commoncrawl.org/CC-MAIN-...-index<br/>?url=*.dominio.com/*&output=json"]
        Q2 --> R2["→ urlsCC/ + cc-200-subs.txt"]

        N --> P3["Shodan"]
        P3 --> Q3["GET → www.shodan.io/domain/dominio.com"]
        Q3 --> R3["→ sh-subs.txt"]

        N --> P4["crt.sh"]
        P4 --> Q4["GET → crt.sh/?q=dominio.com"]
        Q4 --> R4["→ crt-subs.txt"]
    end

    R1 & R2 & R3 & R4 --> T["Unión → subs/all-subs.txt"]

    T --> V["PASO 3: Búsqueda de Archivos Sensibles"]
    V --> Y["Buscar .js, .json, .pdf, .php, .bak, .sql, .zip, .old, etc.<br/>→ js_files/, pdf_files/, bak_files/, sql_files/, ..."]

    Y --> AA["PASO 4: Verificación de Subdominios Activos"]
    subgraph CheckHTTP ["Comprobación estado"]
        direction TB
        AA --> DD["POST → backend-v2.httpstatus.io/api<br/>lotes de 99 + rotación UA"]
        DD --> FF["→ active_http_subdomains.txt"]
        DD --> GG["→ active_https_subdomains.txt"]
    end

    FF & GG --> HH["PASO 5: Capturas de Pantalla"]
    subgraph Gowitness ["GoWitness"]
        direction TB
        HH --> LL["gowitness scan file<br/>-f lista_subdominios_activos"]
        LL --> MM["→ screenshots/ + capturas"]
    end

    MM --> OO["ESCANEO COMPLETADO"]

    %% ESTILOS
    style A fill:#1f2937,color:#fff
    style OO fill:#166534,color:#fff
    style H fill:#1d4ed8,color:#fff
    style N fill:#1d4ed8,color:#fff
    style V fill:#1d4ed8,color:#fff
    style AA fill:#1d4ed8,color:#fff
    style HH fill:#dc2626,color:#fff
    style FuentesSubdominios fill:#1e293b,color:#e2e8f0
    style CheckHTTP fill:#1e293b,color:#e2e8f0
    style Gowitness fill:#7f1d1d,color:#fecaca
```

 

