# Autonomous Web Application Security Assessment Platform (AWASAP)

<p align="center">
  <strong>An Automated Web Application Security Assessment Platform</strong>
</p>

## 📌 About The Project

The **Autonomous Web Application Security Assessment Platform (AWASAP)** is a web-based cybersecurity project designed to automate web application security assessments and help identify potential vulnerabilities.

It provides a centralized dashboard where users can manage security projects, configure targets, execute vulnerability scans, analyze findings, and generate detailed security reports.

The platform integrates automated scanning modules, OWASP-oriented security checks, and AI-assisted vulnerability analysis to make security assessment more accessible and organized.

## 🎯 Project Objectives

- Automate web application security assessment.
- Identify potential security vulnerabilities.
- Provide centralized project and target management.
- Analyze vulnerabilities based on severity and evidence.
- Provide OWASP Top 10-oriented security assessment.
- Generate structured security reports.
- Support AI-assisted vulnerability explanations and remediation guidance.

## 🚀 Key Features

### 1. User Authentication
- User registration and login.
- JWT-based authentication.
- Password hashing using bcrypt.

### 2. Dashboard
- Security assessment overview.
- Scan activity and status.
- Vulnerability statistics.
- Findings overview.

### 3. Project Management
- Create and manage security projects.
- Organize assessment targets.
- Track project-related scans.

### 4. Automated Vulnerability Scanner
- Reconnaissance and information gathering.
- Website crawling and endpoint discovery.
- Security header analysis.
- SSL/TLS security assessment.
- SQL Injection detection checks.
- Cross-Site Scripting (XSS) checks.
- CSRF assessment.
- IDOR checks.
- JWT and API security checks.
- Open redirect and other security checks.

### 5. OWASP Top 10 Assessment
The platform includes checker modules corresponding to OWASP Top 10 categories (A01–A10).

### 6. Findings Management
- Vulnerability classification.
- Severity-based findings.
- Evidence and technical details.
- Remediation recommendations.

### 7. AI Security Assistant
- AI-assisted vulnerability explanations.
- Security recommendations.
- Remediation guidance.
- Configurable Gemini, OpenAI, and Mock providers.

### 8. Security Reports
Generate assessment reports in multiple formats:

- PDF
- HTML
- JSON
- CSV

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Frontend | React 19, TypeScript |
| Build Tool | Vite 8 |
| Styling | Tailwind CSS 4 |
| UI Components | Radix UI |
| Backend | Python, FastAPI |
| Database | PostgreSQL, SQLite |
| ORM | SQLAlchemy 2 |
| Migrations | Alembic |
| Authentication | JWT, bcrypt |
| HTTP Client | HTTPX |
| AI Integration | Gemini, OpenAI, Mock Provider |
| Reports | ReportLab, Jinja2 |
| Testing | Pytest |
| Deployment | Docker, Docker Compose, Nginx |

## 🏗️ System Architecture

```text
                AWASAP PLATFORM
                       |
          +------------+------------+
          |                         |
      FRONTEND                   BACKEND
   React + TypeScript              FastAPI
          |                         |
          |                    API ROUTES
          |                         |
          |                  AUTHENTICATION
          |                         |
          |                  BUSINESS LOGIC
          |                         |
          |                   SCANNER ENGINE
          |                         |
          |             +-----------+-----------+
          |             |                       |
          |       SCAN MODULES             OWASP CHECKERS
          |             |                       |
          |             +-----------+-----------+
          |                         |
          |                     FINDINGS
          |                         |
          |                  AI ASSISTANT
          |                         |
          |                   REPORT ENGINE
          |                         |
          |                     DATABASE
          |                  PostgreSQL/SQLite
```

## 📂 Project Structure

```text
AWASAP/
│
├── backend/
│   ├── alembic/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── database/
│   │   ├── models/
│   │   ├── repositories/
│   │   ├── schemas/
│   │   └── services/
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
│
├── src/
│   ├── app/
│   ├── components/
│   ├── features/
│   ├── services/
│   ├── stores/
│   └── types/
│
├── public/
├── docs/
├── dataset/
├── scripts/
│
├── docker-compose.yml
├── Dockerfile
├── nginx.conf
├── package.json
├── pnpm-lock.yaml
├── vite.config.ts
└── README.md
```

## ⚙️ Installation and Setup

### Prerequisites

Make sure the following tools are installed:

- Python 3.11+
- Node.js 22+
- npm
- PostgreSQL (if using PostgreSQL)
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/ankithexlab/Autonomous-Web-Application-Security-Assessment-Platform.git
```

```bash
cd Autonomous-Web-Application-Security-Assessment-Platform
```

### Step 2: Backend Setup

Open a terminal:

```powershell
cd backend
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Configure environment variables using the provided `.env.example` file.

Create your own secret key and configure your database connection and AI provider settings as required.

Run database migrations:

```powershell
alembic upgrade head
```

Start the backend:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Step 3: Frontend Setup

Open another terminal in the project root:

```powershell
npm install
```

Start the frontend:

```powershell
npm run dev
```

### Step 4: Open the Application

Frontend:

```text
http://localhost:5173
```

Backend:

```text
http://127.0.0.1:8000
```

## 📖 API Documentation

AWASAP uses FastAPI for backend API development.

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

Alternative API documentation:

```text
http://127.0.0.1:8000/redoc
```

## 🧪 Testing

Run backend tests from the backend directory:

```powershell
pytest tests -q
```

Build the frontend:

```powershell
npm run build
```

Run frontend lint checks:

```powershell
npm run lint
```

## 🐳 Docker Support

The project includes Docker and Docker Compose configuration.

To build and start the configured services:

```bash
docker compose up --build
```

To stop the services:

```bash
docker compose down
```

Review the Docker configuration and replace development credentials and secret values before deployment.

## 🔐 Security Disclaimer

AWASAP is developed for educational purposes and authorized security assessments.

- Scan only websites and applications for which you have explicit permission.
- Do not perform unauthorized vulnerability testing.
- Use controlled testing environments whenever possible.
- Avoid destructive testing against production applications.
- Verify findings manually before treating them as confirmed vulnerabilities.
- Keep API keys, passwords, database credentials, and secret keys private.

Automated scanning cannot guarantee the detection of every vulnerability or prove that an application is secure.

## 🔮 Future Scope

- Improve vulnerability detection accuracy.
- Expand security assessment coverage.
- Enhance authenticated scanning capabilities.
- Improve AI-assisted security analysis.
- Reduce false-positive findings.
- Add more reporting and monitoring capabilities.
- Improve deployment and scalability.

## 👨‍💻 Project Information

| Detail | Information |
|---|---|
| Project Name | Autonomous Web Application Security Assessment Platform |
| Short Name | AWASAP |
| Domain | Cyber Security |
| Specialization | Web Application Security |
| Project Type | Academic Project |
| Semester | BCA 5th Semester |

## 🔗 GitHub Repository

[Autonomous Web Application Security Assessment Platform – GitHub](https://github.com/ankithexlab/Autonomous-Web-Application-Security-Assessment-Platform)

---

**Developed with a focus on cybersecurity, automation, and web application security assessment.**
