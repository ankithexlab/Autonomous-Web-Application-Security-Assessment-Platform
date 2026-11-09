/**
 * Scanner Modules Data — dummy data for all scanner module categories
 * and their results for UI preview purposes.
 */

import type { ScanModule } from "@/types"

/* ── Module Definitions ── */

export interface ScannerModuleDefinition {
  id: string
  name: string
  description: string
  category: "Information Gathering" | "Security Analysis" | "OWASP Top 10" | "Vulnerability Detection"
  icon: string
}

export const SCANNER_MODULE_DEFINITIONS: ScannerModuleDefinition[] = [
  // Information Gathering
  { id: "dns_lookup", name: "DNS Lookup", description: "Resolve A, AAAA, MX, NS, TXT, CNAME, SOA records and detect misconfigurations", category: "Information Gathering", icon: "Globe" },
  { id: "whois_lookup", name: "WHOIS Lookup", description: "Query domain registration data, expiry dates, and registrar information", category: "Information Gathering", icon: "Search" },
  { id: "ip_detection", name: "IP Detection", description: "Resolve IP addresses, reverse DNS, CDN/hosting provider detection", category: "Information Gathering", icon: "Server" },
  { id: "tech_detection", name: "Technology Detection", description: "Fingerprint web technologies, frameworks, CMS, and JavaScript libraries", category: "Information Gathering", icon: "Cpu" },
  { id: "directory_discovery", name: "Directory Discovery", description: "Probe for exposed sensitive paths (.git, .env, admin panels, backups)", category: "Information Gathering", icon: "FolderSearch" },
  // Security Analysis
  { id: "cors_analyzer", name: "CORS Analysis", description: "Analyze Cross-Origin Resource Sharing configuration for misconfigurations", category: "Security Analysis", icon: "Shield" },
  { id: "session_analyzer", name: "Session Management", description: "Deep session cookie analysis: entropy, scope, persistence, fixation", category: "Security Analysis", icon: "Key" },
  { id: "security_headers", name: "Security Headers", description: "Audit HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers", category: "Security Analysis", icon: "ShieldCheck" },
  { id: "cookie_audit", name: "Cookie Security", description: "Verify Secure, HttpOnly, SameSite cookie attributes", category: "Security Analysis", icon: "Cookie" },
  { id: "ssl_tls", name: "SSL/TLS Analysis", description: "HTTPS enforcement, redirect chain, certificate analysis", category: "Security Analysis", icon: "Lock" },
  // OWASP Top 10
  { id: "a01_access_control", name: "A01: Broken Access Control", description: "Detect access control failures and authorization bypasses", category: "OWASP Top 10", icon: "ShieldAlert" },
  { id: "a02_crypto_failures", name: "A02: Cryptographic Failures", description: "Identify weak cryptography and data exposure risks", category: "OWASP Top 10", icon: "KeyRound" },
  { id: "a03_injection", name: "A03: Injection", description: "Detect injection vulnerabilities from response analysis", category: "OWASP Top 10", icon: "Syringe" },
  { id: "a04_insecure_design", name: "A04: Insecure Design", description: "Identify insecure design patterns and missing controls", category: "OWASP Top 10", icon: "AlertTriangle" },
  { id: "a05_misconfiguration", name: "A05: Security Misconfiguration", description: "Detect server and application misconfigurations", category: "OWASP Top 10", icon: "Settings" },
  { id: "a06_vulnerable_components", name: "A06: Vulnerable Components", description: "Identify outdated or vulnerable third-party components", category: "OWASP Top 10", icon: "Package" },
  { id: "a07_auth_failures", name: "A07: Auth Failures", description: "Authentication and session management weaknesses", category: "OWASP Top 10", icon: "UserX" },
  { id: "a08_software_integrity", name: "A08: Software Integrity", description: "Check for integrity verification failures", category: "OWASP Top 10", icon: "FileCheck" },
  { id: "a09_logging_failures", name: "A09: Logging Failures", description: "Detect insufficient logging and monitoring", category: "OWASP Top 10", icon: "FileWarning" },
  { id: "a10_ssrf", name: "A10: SSRF", description: "Server-Side Request Forgery detection", category: "OWASP Top 10", icon: "Unlink" },
  // Vulnerability Detection
  { id: "sqli_detector", name: "SQL Injection", description: "Passive detection of SQL error messages and injectable parameters", category: "Vulnerability Detection", icon: "Database" },
  { id: "xss_detector", name: "XSS Detection", description: "Identify DOM-based XSS sinks, sources, and inline handlers", category: "Vulnerability Detection", icon: "Code" },
  { id: "csrf_detector", name: "CSRF Analysis", description: "Check forms for CSRF token protection and SameSite cookies", category: "Vulnerability Detection", icon: "ShieldOff" },
  { id: "idor_detector", name: "IDOR Detection", description: "Detect sequential/predictable object IDs in URLs and responses", category: "Vulnerability Detection", icon: "Hash" },
  { id: "open_redirect", name: "Open Redirect", description: "Find redirect parameters and cross-domain redirect chains", category: "Vulnerability Detection", icon: "ExternalLink" },
  { id: "cmd_injection", name: "Command Injection", description: "Detect OS command execution patterns and CGI paths in responses", category: "Vulnerability Detection", icon: "Terminal" },
  { id: "jwt_analyzer", name: "JWT Analysis", description: "Decode and analyze JWT tokens for weak algorithms and sensitive data", category: "Vulnerability Detection", icon: "KeySquare" },
  { id: "api_security", name: "API Security", description: "Check rate limiting, error verbosity, versioning, and pagination", category: "Vulnerability Detection", icon: "Plug" },
  { id: "file_upload", name: "File Upload", description: "Detect upload forms and check for type restriction enforcement", category: "Vulnerability Detection", icon: "Upload" },
  { id: "rate_limit", name: "Rate Limiting", description: "Verify rate limiting on main pages and authentication endpoints", category: "Vulnerability Detection", icon: "Gauge" },
]

/* ── Dummy Module Results ── */

export interface DNSRecord {
  type: string
  value: string
  priority?: number
}

export interface WHOISData {
  registrar: string
  creationDate: string
  expirationDate: string
  nameServers: string[]
  registrantCountry: string
  daysUntilExpiry: number
}

export interface DetectedTechnology {
  name: string
  category: string
  version: string
  confidence: string
}

export interface DiscoveredPath {
  path: string
  name: string
  statusCode: number
  severity: string
}

export interface ModuleResults {
  dns?: {
    hostname: string
    records: DNSRecord[]
  }
  whois?: WHOISData
  ip?: {
    ipv4: string[]
    ipv6: string[]
    reverseDns: { ip: string; hostname: string }[]
    cdnDetected: string | null
    hostingProvider: string | null
  }
  technologies?: DetectedTechnology[]
  directories?: {
    pathsChecked: number
    discovered: DiscoveredPath[]
  }
}

export const DUMMY_MODULE_RESULTS: ModuleResults = {
  dns: {
    hostname: "app.acmecorp.com",
    records: [
      { type: "A", value: "104.26.10.78" },
      { type: "A", value: "104.26.11.78" },
      { type: "AAAA", value: "2606:4700:20::681a:a4e" },
      { type: "MX", value: "mail.acmecorp.com", priority: 10 },
      { type: "MX", value: "mail2.acmecorp.com", priority: 20 },
      { type: "NS", value: "ns1.cloudflare.com" },
      { type: "NS", value: "ns2.cloudflare.com" },
      { type: "TXT", value: "v=spf1 include:_spf.google.com ~all" },
      { type: "TXT", value: "v=DMARC1; p=reject; rua=mailto:dmarc@acmecorp.com" },
      { type: "CNAME", value: "acmecorp.com.cdn.cloudflare.net" },
    ],
  },
  whois: {
    registrar: "Namecheap, Inc.",
    creationDate: "2019-03-15",
    expirationDate: "2027-03-15",
    nameServers: ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    registrantCountry: "US",
    daysUntilExpiry: 565,
  },
  ip: {
    ipv4: ["104.26.10.78", "104.26.11.78"],
    ipv6: ["2606:4700:20::681a:a4e"],
    reverseDns: [
      { ip: "104.26.10.78", hostname: "cdn-104-26-10-78.cloudflare.com" },
    ],
    cdnDetected: "Cloudflare",
    hostingProvider: "Cloudflare",
  },
  technologies: [
    { name: "React", category: "JavaScript Library", version: "18.2", confidence: "HIGH" },
    { name: "Next.js", category: "Framework", version: "14.1", confidence: "HIGH" },
    { name: "Cloudflare", category: "CDN", version: "", confidence: "HIGH" },
    { name: "Node.js", category: "Runtime", version: "", confidence: "MEDIUM" },
    { name: "Tailwind CSS", category: "CSS Framework", version: "3.4", confidence: "HIGH" },
    { name: "Font Awesome", category: "Icon Library", version: "", confidence: "MEDIUM" },
  ],
  directories: {
    pathsChecked: 30,
    discovered: [
      { path: "/.git/HEAD", name: "Git Repository", statusCode: 200, severity: "high" },
      { path: "/api/docs", name: "API Documentation", statusCode: 200, severity: "info" },
      { path: "/admin/", name: "Admin Panel", statusCode: 403, severity: "info" },
      { path: "/.DS_Store", name: "macOS DS_Store", statusCode: 200, severity: "low" },
    ],
  },
}

/* ── Dummy Completed Modules for Scan Detail ── */

export const DUMMY_SCAN_MODULES: ScanModule[] = [
  // Information Gathering
  { id: "mod-dns", name: "DNS Lookup", description: "DNS record resolution and analysis", status: "completed", progress: 100, findingsCount: 0, startedAt: "2026-07-30T15:00:00Z", completedAt: "2026-07-30T15:00:05Z", duration: "5s" },
  { id: "mod-whois", name: "WHOIS Lookup", description: "Domain registration data", status: "completed", progress: 100, findingsCount: 0, startedAt: "2026-07-30T15:00:05Z", completedAt: "2026-07-30T15:00:08Z", duration: "3s" },
  { id: "mod-ip", name: "IP Detection", description: "IP resolution & CDN detection", status: "completed", progress: 100, findingsCount: 0, startedAt: "2026-07-30T15:00:08Z", completedAt: "2026-07-30T15:00:10Z", duration: "2s" },
  { id: "mod-tech", name: "Technology Detection", description: "Technology fingerprinting", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:00:10Z", completedAt: "2026-07-30T15:00:15Z", duration: "5s" },
  { id: "mod-dirs", name: "Directory Discovery", description: "Sensitive path scanning", status: "completed", progress: 100, findingsCount: 2, startedAt: "2026-07-30T15:00:15Z", completedAt: "2026-07-30T15:00:45Z", duration: "30s" },
  // Security Analysis
  { id: "mod-headers", name: "Security Headers", description: "HTTP header security audit", status: "completed", progress: 100, findingsCount: 3, startedAt: "2026-07-30T15:00:45Z", completedAt: "2026-07-30T15:00:48Z", duration: "3s" },
  { id: "mod-cookies", name: "Cookie Security", description: "Cookie attribute audit", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:00:48Z", completedAt: "2026-07-30T15:00:49Z", duration: "1s" },
  { id: "mod-cors", name: "CORS Analysis", description: "Cross-origin policy check", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:00:49Z", completedAt: "2026-07-30T15:00:51Z", duration: "2s" },
  { id: "mod-session", name: "Session Management", description: "Session security analysis", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:00:51Z", completedAt: "2026-07-30T15:00:53Z", duration: "2s" },
  { id: "mod-ssl", name: "SSL/TLS Analysis", description: "HTTPS & redirect analysis", status: "completed", progress: 100, findingsCount: 0, startedAt: "2026-07-30T15:00:53Z", completedAt: "2026-07-30T15:00:55Z", duration: "2s" },
  // OWASP
  { id: "mod-owasp", name: "OWASP Top 10", description: "A01-A10 security checks", status: "completed", progress: 100, findingsCount: 4, startedAt: "2026-07-30T15:00:55Z", completedAt: "2026-07-30T15:01:10Z", duration: "15s" },
  // Vulnerability Detection
  { id: "mod-sqli", name: "SQL Injection", description: "SQL error message scanning", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:01:10Z", completedAt: "2026-07-30T15:01:15Z", duration: "5s" },
  { id: "mod-xss", name: "XSS Detection", description: "DOM XSS sink/source analysis", status: "completed", progress: 100, findingsCount: 2, startedAt: "2026-07-30T15:01:15Z", completedAt: "2026-07-30T15:01:20Z", duration: "5s" },
  { id: "mod-csrf", name: "CSRF Analysis", description: "CSRF token presence check", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:01:20Z", completedAt: "2026-07-30T15:01:23Z", duration: "3s" },
  { id: "mod-idor", name: "IDOR Detection", description: "Sequential ID detection", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:01:23Z", completedAt: "2026-07-30T15:01:25Z", duration: "2s" },
  { id: "mod-redirect", name: "Open Redirect", description: "Redirect parameter detection", status: "completed", progress: 100, findingsCount: 0, startedAt: "2026-07-30T15:01:25Z", completedAt: "2026-07-30T15:01:27Z", duration: "2s" },
  { id: "mod-jwt", name: "JWT Analysis", description: "JWT token security analysis", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:01:27Z", completedAt: "2026-07-30T15:01:29Z", duration: "2s" },
  { id: "mod-api", name: "API Security", description: "API security patterns check", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:01:29Z", completedAt: "2026-07-30T15:01:32Z", duration: "3s" },
  { id: "mod-upload", name: "File Upload", description: "Upload form detection", status: "completed", progress: 100, findingsCount: 0, startedAt: "2026-07-30T15:01:32Z", completedAt: "2026-07-30T15:01:33Z", duration: "1s" },
  { id: "mod-ratelimit", name: "Rate Limiting", description: "Rate limit header check", status: "completed", progress: 100, findingsCount: 1, startedAt: "2026-07-30T15:01:33Z", completedAt: "2026-07-30T15:01:38Z", duration: "5s" },
]

export const MODULE_CATEGORIES = [
  "Information Gathering",
  "Security Analysis",
  "OWASP Top 10",
  "Vulnerability Detection",
] as const
