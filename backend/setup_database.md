# Database Setup Guide

This guide covers setting up PostgreSQL for the Semio freemium system with production-ready best practices.

## 🗄️ PostgreSQL Setup

### 1. Install PostgreSQL

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
```

#### macOS (using Homebrew):
```bash
brew install postgresql
brew services start postgresql
```

#### Windows:
Download from [PostgreSQL official website](https://www.postgresql.org/download/windows/)

### 2. Create Database and User

```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Create database
CREATE DATABASE semio_db;

# Create user with limited privileges
CREATE USER semio_user WITH PASSWORD 'semio_password';

# Grant privileges
GRANT CONNECT ON DATABASE semio_db TO semio_user;
GRANT USAGE ON SCHEMA public TO semio_user;
GRANT CREATE ON SCHEMA public TO semio_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO semio_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO semio_user;

# Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO semio_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO semio_user;

# Exit PostgreSQL
\q
```

### 3. Environment Configuration

Create `.env` file in the `backend` directory:

```env
# Database Configuration
DATABASE_URL=postgresql://semio_user:semio_password@localhost:5432/semio_db

# Security
SECRET_KEY=your-super-secret-key-change-in-production
GOOGLE_API_KEY=your_google_api_key_here

# Application Settings
DEBUG=False
SQL_ECHO=False

# Optional: Use SQLite for development
# USE_SQLITE=true
```

### 4. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 5. Initialize Database

#### Option A: Automatic (Recommended)
The database will be automatically initialized when you start the application:

```bash
python -m uvicorn app.main:app --reload --port 8000
```

#### Option B: Manual
```bash
cd backend
python -c "from app.database import init_db; init_db()"
```

### 6. Database Migrations (Optional)

For production deployments, use Alembic for database migrations:

```bash
# Initialize Alembic (first time only)
alembic init alembic

# Create a migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations
alembic upgrade head
```

## 🔒 Security Best Practices

### 1. Database Security

```sql
-- Restrict network access (in postgresql.conf)
listen_addresses = 'localhost'

-- Use SSL (in postgresql.conf)
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'

-- Set strong password policies
ALTER USER semio_user PASSWORD 'strong-password-here';
```

### 2. Connection Pooling

The application is configured with connection pooling:

```python
# In app/database.py
engine = create_engine(
    DATABASE_URL,
    pool_size=10,           # Maintain 10 connections
    max_overflow=20,        # Allow 20 additional connections
    pool_pre_ping=True,     # Validate connections
    pool_recycle=3600,      # Recycle connections every hour
)
```

### 3. Environment Variables

Never commit sensitive information to version control:

```bash
# .env (add to .gitignore)
DATABASE_URL=postgresql://user:password@host:port/db
SECRET_KEY=your-secret-key-here
GOOGLE_API_KEY=your-api-key-here
```

## 📊 Database Schema

### Tables Created

1. **users** - User accounts and tier management
2. **usage_logs** - Request tracking and analytics
3. **audit_logs** - Security audit trail
4. **monthly_usage_resets** - Billing cycle tracking
5. **api_keys** - API key management (optional)

### Indexes for Performance

- `idx_users_email_tier` - Fast user lookups
- `idx_users_api_key_active` - API key validation
- `idx_usage_logs_user_date` - Usage analytics
- `idx_audit_logs_user_date` - Audit queries

## 🚀 Production Deployment

### 1. Database Backup

```bash
# Create backup
pg_dump -h localhost -U semio_user -d semio_db > backup.sql

# Restore backup
psql -h localhost -U semio_user -d semio_db < backup.sql
```

### 2. Monitoring

```sql
-- Check connection count
SELECT count(*) FROM pg_stat_activity WHERE datname = 'semio_db';

-- Check table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

### 3. Performance Tuning

```sql
-- Analyze tables for query optimization
ANALYZE users;
ANALYZE usage_logs;
ANALYZE audit_logs;

-- Check slow queries
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements 
WHERE query LIKE '%semio%' 
ORDER BY mean_time DESC;
```

## 🔧 Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check if PostgreSQL is running
   - Verify connection string
   - Check firewall settings

2. **Permission Denied**
   - Verify user privileges
   - Check database ownership
   - Ensure proper grants

3. **Pool Exhaustion**
   - Increase pool_size and max_overflow
   - Check for connection leaks
   - Monitor connection usage

### Useful Commands

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# View logs
sudo tail -f /var/log/postgresql/postgresql-*.log

# Connect to database
psql -h localhost -U semio_user -d semio_db

# List tables
\dt

# Describe table
\d users
```

## 📈 Scaling Considerations

### 1. Read Replicas
For high-traffic applications, consider read replicas:

```python
# Multiple database URLs
DATABASE_URL_MASTER=postgresql://user:pass@master:5432/db
DATABASE_URL_REPLICA=postgresql://user:pass@replica:5432/db
```

### 2. Partitioning
For large datasets, consider table partitioning:

```sql
-- Partition usage_logs by date
CREATE TABLE usage_logs_2024 PARTITION OF usage_logs
FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
```

### 3. Connection Pooling
For production, consider dedicated connection poolers like PgBouncer:

```ini
# pgbouncer.ini
[databases]
semio_db = host=localhost port=5432 dbname=semio_db

[pgbouncer]
listen_port = 6432
listen_addr = localhost
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 20
```

## ✅ Verification

After setup, verify everything works:

```bash
# Test database connection
python -c "
from app.database import SessionLocal
db = SessionLocal()
try:
    result = db.execute('SELECT 1')
    print('Database connection successful!')
finally:
    db.close()
"

# Test API endpoints
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpassword123"}'
```

Your PostgreSQL database is now ready for production use! 🎉
