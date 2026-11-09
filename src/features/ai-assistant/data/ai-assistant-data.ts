import type { Conversation, SuggestedPrompt } from "@/types"

export const SUGGESTED_PROMPTS: SuggestedPrompt[] = [
  {
    id: "sp-1",
    title: "AWASAP Architecture",
    prompt: "What is AWASAP, and what modules are actually implemented?",
    category: "Architecture",
    iconName: "Server",
  },
  {
    id: "sp-2",
    title: "Scanner Engine Location",
    prompt: "Where is the scanner engine implemented and how does it work?",
    category: "Code Audit",
    iconName: "ShieldAlert",
  },
  {
    id: "sp-3",
    title: "Live Scan Findings",
    prompt: "Show my actual scan findings and their severity.",
    category: "Findings",
    iconName: "ShieldAlert",
  },
  {
    id: "sp-4",
    title: "Security Score Logic",
    prompt: "Why does my dashboard show a security score of 100/100?",
    category: "Dashboard",
    iconName: "Lock",
  },
  {
    id: "sp-5",
    title: "SQL Injection Remediation",
    prompt: "How do I fix SQL Injection using parameterized queries and SQLAlchemy?",
    category: "Code Fix",
    iconName: "KeyRound",
  },
  {
    id: "sp-6",
    title: "SSRF Protection",
    prompt: "How does AWASAP block Server-Side Request Forgery (SSRF) and metadata attacks?",
    category: "Network",
    iconName: "ShieldAlert",
  },
]


export const STATIC_RESPONSES: Record<string, string> = {
  sqli: `### SQL Injection (SQLi) Remediation Guide

SQL Injection occurs when untrusted user input is directly concatenated into a raw SQL query string.

#### Key Principles for Remediation
1. **Always Use Parameterized Queries**: Separate SQL code from data variables using prepared statements.
2. **Input Validation & Sanitization**: Enforce strict data types and schema validation.
3. **Principle of Least Privilege**: Ensure the database user has minimal necessary permissions.

#### Code Example (TypeScript / Node.js + pg)

\`\`\`typescript
import { Pool } from 'pg';

const pool = new Pool();

// ❌ VULNERABLE: Direct string interpolation
export async function unsafeGetUser(username: string) {
  const query = \`SELECT id, username, email FROM users WHERE username = '\${username}'\`;
  return await pool.query(query);
}

// ✅ SECURE: Parameterized Query
export async function safeGetUser(username: string) {
  const query = 'SELECT id, username, email FROM users WHERE username = $1';
  return await pool.query(query, [username]);
}
\`\`\`

#### ORM Approach (Prisma / TypeORM)
Using an ORM like Prisma natively prevents SQL injection for standard query builders:

\`\`\`typescript
const user = await prisma.user.findUnique({
  where: { username: req.params.username },
});
\`\`\`

> **Note**: If executing raw SQL queries via \`prisma.$queryRaw\`, always use template tags \`prisma.$queryRaw\`\`...\`\` which automatically parameterizes inputs.`,

  cors: `### Secure CORS Configuration Guide

Cross-Origin Resource Sharing (CORS) misconfigurations can expose your API to unauthorized requests from arbitrary domains.

#### Recommended Production Rules
- Avoid using \`Access-Control-Allow-Origin: *\` when credentials are supported.
- Explicitly whitelist trusted origins.
- Set reasonable \`Access-Control-Max-Age\` values.

#### Node.js / Express Example

\`\`\`typescript
import express from 'express';
import cors from 'cors';

const app = express();

const allowedOrigins = [
  'https://app.acmecorp.com',
  'https://admin.acmecorp.com',
];

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 86400, // 24 hours cache
};

app.use(cors(corsOptions));
\`\`\``,

  bola: `### Broken Object Level Authorization (BOLA / IDOR)

BOLA is the **#1 threat on the OWASP API Security Top 10**. It occurs when an API endpoint accepts an object ID without verifying whether the requesting user has rights to access that specific object.

#### Mitigation Strategy
1. **Validate Ownership on Every Request**: Check \`resource.ownerId === req.user.id\`.
2. **Use Non-Sequential Identifiers**: Prefer UUIDv4 over sequential integer IDs (\`1, 2, 3\`).

\`\`\`typescript
// Express Middleware Example for Resource Authorization
export async function getOrderDetails(req: Request, res: Response) {
  const { orderId } = req.params;
  const currentUserId = req.user.id;

  const order = await db.order.findUnique({ where: { id: orderId } });

  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  // Enforce BOLA authorization check
  if (order.userId !== currentUserId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied: You do not own this resource' });
  }

  return res.json(order);
}
\`\`\``,

  nginx: `### Nginx SSL/TLS Security Hardening (A+ Rating)

Below is an enterprise-grade Nginx configuration snippet enabling **TLS 1.2/1.3**, HSTS, and strong cipher suites.

\`\`\`nginx
server {
    listen 443 ssl http2;
    server_name api.acmecorp.com;

    # SSL Certificates
    ssl_certificate /etc/letsencrypt/live/api.acmecorp.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.acmecorp.com/privkey.pem;

    # TLS Protocols & Cipher Suites
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Hide Nginx version banner
    server_tokens off;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
\`\`\``,

  jwt: `### JWT Authentication Hardening Guide

JSON Web Tokens (JWT) must be strictly verified against unauthorized algorithm switching (e.g. \`alg: none\` attack).

#### Security Best Practices
1. **Explicit Algorithm Whitelisting**: Always specify allowed algorithms when verifying tokens.
2. **Short-Lived Access Tokens**: Use short expiration times (e.g. 15 mins) combined with secure HTTP-only refresh cookies.

\`\`\`typescript
import jwt from 'jsonwebtoken';

const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;

// ✅ SECURE: Enforce RS256 signature verification
export function verifyAccessToken(token: string) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],
    issuer: 'https://auth.acmecorp.com',
  });
}
\`\`\``,

  ssrf: `### Server-Side Request Forgery (SSRF) Prevention

SSRF allows attackers to abuse backend server HTTP client calls to scan internal networks or access AWS instance metadata (169.254.169.254).

#### Remediation Steps
1. **Validate and Whitelist Destination Domains**.
2. **Block Private RFC 1918 & Loopback IP Ranges** prior to issuing outgoing sockets.

\`\`\`typescript
import ipaddr from 'ipaddr.js';

export function isPrivateIp(ipString: string): boolean {
  if (!ipaddr.isValid(ipString)) return true;
  const parsed = ipaddr.parse(ipString);
  const range = parsed.range();
  return range !== 'unicast'; // Blocks 'private', 'loopback', 'linkLocal'
}
\`\`\``,

  default: `### Sentinel AI Security Insight

Thank you for your security inquiry. Here is a general security analysis based on cybersecurity best practices:

1. **Defense in Depth**: Layer controls across network, transport, application, and database boundaries.
2. **Zero Trust Architecture**: Always verify, never trust inputs or internal network connections.
3. **Continuous Monitoring**: Utilize real-time vulnerability scans and automated log analysis.

\`\`\`bash
# Run automated security audit against local packages
npm audit --production
\`\`\`

Feel free to select a suggested prompt or ask specific questions regarding **SQL Injection**, **CORS**, **BOLA**, **JWT**, **SSRF**, or **Nginx Hardening**.`,
}

export const INITIAL_CONVERSATIONS: Conversation[] = [
  {
    id: "conv-1",
    title: "SQL Injection Remediation in Node.js",
    category: "remediation",
    messages: [
      {
        id: "msg-1",
        role: "user",
        content: "How do I fix SQL Injection in a Node.js Express application using PostgreSQL?",
        timestamp: "2026-07-30T14:10:00Z",
      },
      {
        id: "msg-2",
        role: "assistant",
        content: STATIC_RESPONSES.sqli || "",
        timestamp: "2026-07-30T14:10:05Z",
      },
    ],
    createdAt: "2026-07-30T14:10:00Z",
    updatedAt: "2026-07-30T14:10:05Z",
  },
  {
    id: "conv-2",
    title: "CORS Header Configuration Audit",
    category: "code_audit",
    messages: [
      {
        id: "msg-3",
        role: "user",
        content: "Show me a secure CORS configuration for production APIs with credentials support.",
        timestamp: "2026-07-29T16:00:00Z",
      },
      {
        id: "msg-4",
        role: "assistant",
        content: STATIC_RESPONSES.cors || "",
        timestamp: "2026-07-29T16:00:04Z",
      },
    ],
    createdAt: "2026-07-29T16:00:00Z",
    updatedAt: "2026-07-29T16:00:04Z",
  },
]
