CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (already exists - no changes needed)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  is_premium BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Vaults table - ADD trustee_count column if it doesn't exist
CREATE TABLE IF NOT EXISTS vaults (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  encryption_type VARCHAR(50) NOT NULL DEFAULT 'aes-256-gcm',
  unlock_time TIMESTAMP WITH TIME ZONE,
  required_sigs INTEGER NOT NULL DEFAULT 1 CHECK (required_sigs >= 1),
  trustee_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add trustee_count column to existing vaults table if it doesn't exist
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'vaults' AND column_name = 'trustee_count'
  ) THEN
    ALTER TABLE vaults ADD COLUMN trustee_count INTEGER NOT NULL DEFAULT 0;
  END IF;
END $$;

-- Files table (already exists - has required_sigs column)
CREATE TABLE IF NOT EXISTS files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  filesize BIGINT NOT NULL,
  encrypted_path VARCHAR(500) NOT NULL,
  encryption_key BYTEA,  -- Can be NULL for multi-sig
  iv BYTEA NOT NULL,
  auth_tag BYTEA NOT NULL,
  required_sigs INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- NEW TABLE: Vault trustees (stores which trustees are assigned to which vault)
CREATE TABLE IF NOT EXISTS vault_trustees (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  trustee_email VARCHAR(255) NOT NULL,
  share_index INTEGER NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(vault_id, trustee_email)
);

-- NEW TABLE: Trustee share submissions (stores shares submitted for emergency unlock)
CREATE TABLE IF NOT EXISTS trustee_share_submissions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  trustee_email VARCHAR(255) NOT NULL,
  share_data TEXT NOT NULL,
  submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(vault_id, trustee_email)
);

-- Audit logs table (already exists - no changes needed)
CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL,
  description TEXT,
  ip_address INET,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Subscriptions table (already exists - no changes needed)
CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stripe_customer_id VARCHAR(255),
  stripe_subscription_id VARCHAR(255),
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_vaults_owner ON vaults(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_vault ON files(vault_id);
CREATE INDEX IF NOT EXISTS idx_vault_trustees_vault ON vault_trustees(vault_id);
CREATE INDEX IF NOT EXISTS idx_trustee_submissions_vault ON trustee_share_submissions(vault_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);

-- Insert admin user (password: admin123)
-- Correct bcrypt hash for "admin123"
INSERT INTO users (email, password_hash, first_name, last_name, role, is_premium)
VALUES (
  'admin@chronovault.com',
  '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYIeWYgmmK6',
  'Admin',
  'User',
  'admin',
  TRUE
)
ON CONFLICT (email) DO NOTHING;
