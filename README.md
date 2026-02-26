# ChronoVault
Cryptography 
# 🔐 ChronoVault

**Time-Locked Digital Vault with Multi-Signature Security**

ChronoVault is a secure, time-locked digital vault system that uses military-grade encryption (AES-256-GCM) and Shamir Secret Sharing for distributed trust. Perfect for estate planning, sensitive documents, and time-sensitive information.

## ✨ Features

- 🔒 **AES-256-GCM Encryption** - Military-grade authenticated encryption
- 🕐 **Time-Lock Mechanism** - Files unlock automatically at scheduled times
- 👥 **Multi-Signature Security** - Shamir Secret Sharing (2-5 trustees)
- 🔐 **Emergency Unlock** - Threshold-based trustee consensus
- 📧 **Email Notifications** - Automated trustee share distribution
- 📊 **Audit Logging** - Complete activity tracking
- 🌍 **Global Timezone Support** - UTC-based time handling
- 💎 **Premium Plans** - Stripe integration for subscriptions

## 🏗️ Architecture

- **Frontend:** React 18 + Tailwind CSS
- **Backend:** Node.js + Express
- **Database:** PostgreSQL 15
- **Encryption:** Node.js crypto (AES-256-GCM)
- **Secret Sharing:** secrets.js-grempe (Shamir)
- **Deployment:** Docker + Docker Compose

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for local development)
- PostgreSQL 15 (if not using Docker)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/chronovault.git
cd chronovault
```

2. **Set up environment variables:**
```bash
cp .env.example .env
nano .env # Fill in your secrets
```

3. **Generate SSL certificates (for HTTPS):**
```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout nginx/ssl/key.pem \
-out nginx/ssl/cert.pem \
-subj "/CN=localhost"
```

4. **Start with Docker:**
```bash
docker-compose up -d --build
```

5. **Access the application:**
- Frontend: https://localhost
- Backend API: https://localhost/api

### Default Admin Credentials

- Email: `admin@chronovault.com`
- Password: `bigG123`

**⚠️ Change these immediately in production!**

## 🔧 Development Setup

### Frontend Development
```bash
cd frontend
npm install
npm start # Runs on http://localhost:3000
```

### Backend Development
```bash
cd backend
npm install
node server.js # Runs on http://localhost:5000
```

## 🔐 Security Features

### Defense-in-Depth (6 Layers)

1. **Network:** HTTPS/TLS 1.3, HSTS headers
2. **Application:** JWT authentication, rate limiting, CORS
3. **Cryptographic:** AES-256-GCM, Shamir Secret Sharing, bcrypt
4. **Database:** Parameterized queries, encrypted fields
5. **Audit:** Immutable PostgreSQL logs
6. **Filesystem:** Encrypted .enc files, restricted permissions

### Cryptographic Stack

| Layer | Algorithm | Key Size |
|-------|-----------|----------|
| File Encryption | AES-256-GCM | 256-bit |
| Password Hashing | bcrypt | Cost factor 12 |
| Secret Sharing | Shamir (k,n)-threshold | 256-bit |
| Authentication | JWT (HMAC-SHA256) | 256-bit |

## 🧪 Testing
```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd frontend
npm test

# Security penetration tests
npm run test:security
```

## 📦 Deployment

### Production with SSL (Let's Encrypt)
```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Generate certificate
sudo certbot --nginx -d yourdomain.com

# Auto-renewal
sudo certbot renew --dry-run
```

### Environment Variables

See `.env.example` for all required variables.

**Critical:**
- Change `JWT_SECRET` in production
- Use strong `DB_PASSWORD`
- Configure real email SMTP
- Set up Stripe keys for payments

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

