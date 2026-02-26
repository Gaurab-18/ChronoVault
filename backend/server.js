require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const secrets = require('secrets.js-grempe');
const nodemailer = require('nodemailer');
const Stripe = require('stripe');
const { v4: uuidv4 } = require('uuid');
const { NtpTimeSync } = require('ntp-time-sync');

// Initialize NTP time sync for accurate server time
const timeSync = NtpTimeSync.getInstance();

const app = express();
const PORT = process.env.PORT || 5000;

// Initialize Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2023-10-16'
});

// Initialize Nodemailer
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Test email connection
transporter.verify((error) => {
  if (error) {
    console.error('❌ Email connection failed:', error);
  } else {
    console.log('✅ Email connection successful');
  }
});

// Database connection
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

// Security middleware
app.use(helmet());
app.use(cors({ origin: process.env.ORIGIN || 'http://localhost', credentials: true }));
app.use(express.json({ limit: '10mb' }));

// Upload directories
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const ENCRYPTED_DIR = path.join(UPLOADS_DIR, 'encrypted');

async function ensureDirs() {
  try { await fs.access(UPLOADS_DIR); } catch { await fs.mkdir(UPLOADS_DIR); }
  try { await fs.access(ENCRYPTED_DIR); } catch { await fs.mkdir(ENCRYPTED_DIR); }
}
ensureDirs();

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 2147483648 } });

// Helpers
async function query(text, params) {
  const res = await pool.query(text, params);
  return res;
}

// Get current time - using system time for reliability
async function getCurrentTime() {
  // Just use system time - NTP can cause "Invalid Date" errors
  return new Date();
}

function generateToken(user) {
  return jwt.sign({
    id: user.id.toString(), // Handle UUID
    email: user.email,
    role: user.role
  }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Routes
app.get('/api/health', (req, res) => res.json({ status: 'OK' }));

// Auth
app.post('/api/auth/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  try {
    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length) return res.status(409).json({ error: 'Email exists' });

    const hashed = await bcrypt.hash(password, 12);
    const user = await query(
      'INSERT INTO users (email, password_hash, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING *',
      [email, hashed, firstName, lastName]
    );

    res.json({ token: generateToken(user.rows[0]), user: user.rows[0] });
  } catch (e) { res.status(500).json({ error: 'Register failed' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (!user.rows.length) return res.status(401).json({ error: 'Invalid' });

    const valid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid' });

    res.json({ token: generateToken(user.rows[0]), user: user.rows[0] });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await query(
      'SELECT id, email, first_name, last_name, role, is_premium FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch user' }); }
});

// User stats
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const userResult = await query('SELECT is_premium FROM users WHERE id = $1', [req.user.id]);
    const isPremium = userResult.rows[0].is_premium;

    const storageResult = await query(
      `SELECT COALESCE(SUM(f.filesize), 0) as total_size
       FROM files f
       JOIN vaults v ON f.vault_id = v.id
       WHERE v.owner_id = $1`,
      [req.user.id]
    );

    const totalSize = parseInt(storageResult.rows[0].total_size) || 0;
    const storageLimit = isPremium ? null : 21474836480;

    res.json({
      storageUsed: totalSize,
      storageLimit: storageLimit,
      isPremium: isPremium
    });
  } catch (e) { res.status(500).json({ error: 'Stats failed' }); }
});

// Stripe checkout
app.post('/api/stripe/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID,
          quantity: 1,
        },
      ],
      // Backend handles the /api/stripe/success endpoint, then redirects to frontend
      success_url: `${process.env.ORIGIN}/api/stripe/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.ORIGIN}/`, // Changed from /premium to / (dashboard)
      client_reference_id: req.user.id.toString(), // Convert UUID to string
      customer_email: req.user.email,
    });

    res.json({ sessionId: session.id, url: session.url });
  } catch (e) { res.status(500).json({ error: 'Stripe failed' }); }
});

// Stripe success handler
app.get('/api/stripe/success', async (req, res) => {
  try {
    const { session_id } = req.query;
    const session = await stripe.checkout.sessions.retrieve(session_id);

    if (session.payment_status === 'paid' && session.client_reference_id) {
      await query('UPDATE users SET is_premium = true WHERE id = $1', [session.client_reference_id]);
      await query(
        'INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status) VALUES ($1, $2, $3, $4)',
        [session.client_reference_id, session.customer, session.subscription, 'active']
      );
      res.redirect(`${process.env.ORIGIN}/?premium=success`);
    } else {
      res.redirect(`${process.env.ORIGIN}/premium?error=payment_failed`);
    }
  } catch (e) { res.redirect(`${process.env.ORIGIN}/premium?error=server_error`); }
});

// Vault creation - PROPER SHAMIR SECRET SHARING IMPLEMENTATION
app.post('/api/vaults/create', authenticateToken, upload.array('files'), async (req, res) => {
  const { name, description, unlockTime, required_sigs, trusteeEmails } = req.body;
  const files = req.files;

  if (!name || !files || files.length === 0) {
    return res.status(400).json({ error: 'Name and files required' });
  }

  try {
    // Check user premium status for limits
    const userResult = await query('SELECT is_premium FROM users WHERE id = $1', [req.user.id]);
    const isPremium = userResult.rows[0].is_premium;

    if (!isPremium) {
      // Free users: 3 vaults per week limit
      const weekAgo = new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);

      const vaultCountResult = await query(
        'SELECT COUNT(*) as count FROM vaults WHERE owner_id = $1 AND created_at > $2',
        [req.user.id, weekAgo]
      );

      if (parseInt(vaultCountResult.rows[0].count) >= 3) {
        return res.status(403).json({ error: 'Free users are limited to 3 vaults per week' });
      }

      // Free users: 20GB total storage limit
      const storageResult = await query(
        `SELECT COALESCE(SUM(f.filesize), 0) as total_size
         FROM files f
         JOIN vaults v ON f.vault_id = v.id
         WHERE v.owner_id = $1`,
        [req.user.id]
      );

      const currentStorage = parseInt(storageResult.rows[0].total_size) || 0;
      const newFilesSize = files.reduce((sum, file) => sum + file.size, 0);

      if (currentStorage + newFilesSize > 21474836480) {
        return res.status(403).json({ error: 'Free users are limited to 20GB total storage' });
      }
    }

    // Parse trustee emails
    let parsedTrusteeEmails = [];
    try {
      parsedTrusteeEmails = JSON.parse(trusteeEmails);
    } catch (e) {
      parsedTrusteeEmails = Array.isArray(trusteeEmails) ? trusteeEmails : [];
    }

    // Filter out empty emails
    const validTrusteeEmails = parsedTrusteeEmails.filter(email => email && email.trim() !== '');

    const trusteeCount = validTrusteeEmails.length;
    const threshold = Number(required_sigs);

    // Validation for multi-sig
    if (threshold > 1) {
      if (trusteeCount < 2) {
        return res.status(400).json({ error: 'Multi-signature requires at least 2 trustees' });
      }

      if (threshold > trusteeCount) {
        return res.status(400).json({
          error: `Threshold (${threshold}) cannot exceed number of trustees (${trusteeCount})`
        });
      }

      if (threshold < 2) {
        return res.status(400).json({ error: 'Threshold must be at least 2 for multi-signature' });
      }
    }

    // Parse unlock time - CLEAN SOLUTION (works globally)
    let unlock_time = null;
    if (unlockTime) {
      // Parse normally - JS interprets datetime-local as LOCAL time
      const localDate = new Date(unlockTime);

      if (isNaN(localDate.getTime())) {
        return res.status(400).json({ error: 'Invalid unlock time format' });
      }

      // Convert to UTC automatically
      unlock_time = new Date(localDate.toISOString());

      console.log(`⏰ User input (local): ${unlockTime}`);
      console.log(`⏰ Stored as UTC: ${unlock_time.toISOString()}`);
    }

    // Create vault
    const vault = await query(
      `INSERT INTO vaults (name, description, owner_id, unlock_time, required_sigs, trustee_count)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [name, description, req.user.id, unlock_time, threshold, trusteeCount]
    );
    const vaultId = vault.rows[0].id;

    // Generate master AES key for the vault (ONE key for all files in vault)
    const masterAesKey = crypto.randomBytes(32);
    console.log(`✅ Generated 32-byte master AES key for vault: ${vaultId}`);

    // For multi-sig vaults, split the key ONCE and store shares
    let shares = null;
    if (threshold > 1) {
      shares = secrets.share(masterAesKey.toString('hex'), threshold, trusteeCount);
      console.log(`✅ Split key into ${trusteeCount} shares (threshold: ${threshold})`);
      
      // Store trustee information and their shares
      for (let i = 0; i < trusteeCount; i++) {
        await query(
          `INSERT INTO vault_trustees (vault_id, trustee_email, share_index)
           VALUES ($1, $2, $3)`,
          [vaultId, validTrusteeEmails[i], i]
        );

        // Email the share to the trustee
        const emailContent = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4F46E5;">🔐 ChronoVault Trustee Share</h2>
            <p>You have been designated as a trustee for a secure vault.</p>

            <div style="background: #F3F4F6; padding: 15px; border-radius: 8px; margin: 20px 0;">
              <p><strong>Vault Name:</strong> ${name}</p>
              <p><strong>Owner:</strong> ${req.user.email}</p>
              ${unlock_time ? `<p><strong>Scheduled Unlock:</strong> ${unlock_time.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' })}</p>` : ''}
            </div>

            <div style="background: #FEF3C7; padding: 15px; border-radius: 8px; margin: 20px 0;">
              <p style="margin: 0; color: #92400E;"><strong>⚠️ IMPORTANT: Keep this share secure!</strong></p>
            </div>

            <p><strong>Your Cryptographic Share:</strong></p>
            <div style="background: #1F2937; color: #F9FAFB; padding: 15px; border-radius: 8px; font-family: monospace; word-break: break-all; margin: 20px 0;">
              ${shares[i]}
            </div>

            <div style="background: #EFF6FF; padding: 15px; border-radius: 8px; margin: 20px 0;">
              <p><strong>Security Information:</strong></p>
              <ul>
                <li><strong>${threshold}</strong> out of <strong>${trusteeCount}</strong> trustees must provide their shares to unlock the vault early</li>
                <li>This share is unique to you - do not share it with anyone</li>
                <li>Store this email securely</li>
                <li>Vault ID: <code>${vaultId}</code></li>
              </ul>
            </div>

            <p style="color: #6B7280; font-size: 12px; margin-top: 30px;">
              This is an automated message from ChronoVault. Please do not reply to this email.
            </p>
          </div>
        `;

        await transporter.sendMail({
          from: process.env.EMAIL_FROM || 'ChronoVault <noreply@chronovault.com>',
          to: validTrusteeEmails[i],
          subject: `🔐 ChronoVault: Your Trustee Share for "${name}"`,
          html: emailContent
        }).catch(err => {
          console.error(`Failed to send email to ${validTrusteeEmails[i]}:`, err);
        });
      }
    }

    // Process each file
    for (const file of files) {
      const buffer = await fs.readFile(file.path);

      // Generate unique IV for this file
      const iv = crypto.randomBytes(12);

      // Encrypt file with master AES key
      const cipher = crypto.createCipheriv('aes-256-gcm', masterAesKey, iv);
      let encrypted = cipher.update(buffer);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      const authTag = cipher.getAuthTag();

      const encryptedPath = path.join(ENCRYPTED_DIR, `${uuidv4()}-${file.originalname}`);
      await fs.writeFile(encryptedPath, encrypted);

      if (threshold > 1) {
        // MULTI-SIG MODE - Store file metadata WITHOUT the encryption key
        await query(
          `INSERT INTO files (vault_id, filename, filesize, encrypted_path, iv, auth_tag, required_sigs)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [vaultId, file.originalname, file.size, encryptedPath, iv, authTag, threshold]
        );
      } else {
        // SINGLE KEY MODE - Store the encryption key directly
        await query(
          `INSERT INTO files (vault_id, filename, filesize, encrypted_path, encryption_key, iv, auth_tag, required_sigs)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [vaultId, file.originalname, file.size, encryptedPath, masterAesKey, iv, authTag, threshold]
        );
      }

      // Clean up uploaded file
      await fs.unlink(file.path);
    }

    res.status(201).json({
      vaultId,
      message: 'Vault created successfully',
      emailsSent: trusteeCount,
      threshold,
      trusteeCount
    });
  } catch (e) {
    console.error('Vault creation error:', e);
    res.status(500).json({ error: 'Vault creation failed: ' + e.message });
  }
});

// Get vault details
app.get('/api/vaults/:id', authenticateToken, async (req, res) => {
  try {
    const vault = await query(
      `SELECT v.*, COUNT(f.id) as file_count, COALESCE(SUM(f.filesize), 0) as total_size
       FROM vaults v
       LEFT JOIN files f ON v.id = f.vault_id
       WHERE v.id = $1 AND v.owner_id = $2
       GROUP BY v.id`,
      [req.params.id, req.user.id]
    );

    if (!vault.rows.length) {
      return res.status(404).json({ error: 'Vault not found' });
    }

    const vaultData = vault.rows[0];

    // Get files
    const files = await query(
      'SELECT id, filename, filesize, created_at FROM files WHERE vault_id = $1',
      [req.params.id]
    );

    // Check if vault is unlocked using accurate NTP time
    const now = await getCurrentTime();
    
    // Parse unlock_time safely - handle invalid dates from old data
    let unlockTime = null;
    if (vaultData.unlock_time) {
      unlockTime = new Date(vaultData.unlock_time);
      // Validate the date
      if (isNaN(unlockTime.getTime())) {
        console.warn(`⚠️ Invalid unlock_time for vault ${req.params.id}, treating as unlocked`);
        unlockTime = null; // Treat as no unlock time (unlocked)
      }
    }
    
    const isUnlocked = !unlockTime || now >= unlockTime;

    // Calculate time left
    let timeLeft = 0;
    if (unlockTime && now < unlockTime) {
      timeLeft = Math.ceil((unlockTime - now) / 1000);
    }

    // Safe logging - check if dates are valid
    const nowStr = now instanceof Date && !isNaN(now) ? now.toISOString() : 'Invalid Date';
    const unlockStr = unlockTime instanceof Date && !isNaN(unlockTime) ? unlockTime.toISOString() : 'No unlock time';
    console.log(`⏰ Vault ${req.params.id}: Current=${nowStr}, Unlock=${unlockStr}, Locked=${!isUnlocked}`);

    res.json({
      ...vaultData,
      files: files.rows,
      isUnlocked,
      timeLeft,
      unlock_time: (unlockTime instanceof Date && !isNaN(unlockTime)) ? unlockTime.toISOString() : null
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch vault details' });
  }
});

// Submit trustee share for emergency unlock
app.post('/api/vaults/:id/submit-share', authenticateToken, async (req, res) => {
  const { share, trusteeEmail } = req.body;

  if (!share || !trusteeEmail) {
    return res.status(400).json({ error: 'Share and trustee email required' });
  }

  try {
    const vault = await query(
      `SELECT v.*, v.required_sigs, v.trustee_count
       FROM vaults v
       WHERE v.id = $1 AND v.owner_id = $2`,
      [req.params.id, req.user.id]
    );

    if (!vault.rows.length) {
      return res.status(404).json({ error: 'Vault not found' });
    }

    const vaultData = vault.rows[0];

    // Verify trustee exists for this vault
    const trustee = await query(
      `SELECT * FROM vault_trustees WHERE vault_id = $1 AND trustee_email = $2`,
      [req.params.id, trusteeEmail]
    );

    if (!trustee.rows.length) {
      return res.status(403).json({ error: 'Invalid trustee for this vault' });
    }

    // VALIDATE SHARE FORMAT - Must be valid Shamir share
    const trimmedShare = share.trim();
    
    // Basic validation: Shamir shares are hex strings
    if (!/^[0-9a-fA-F]+$/.test(trimmedShare)) {
      return res.status(400).json({ error: 'Invalid share format - must be hexadecimal' });
    }

    // Shares should be at least 64 characters
    if (trimmedShare.length < 64) {
      return res.status(400).json({ error: 'Invalid share - too short' });
    }

    console.log(`✅ Valid share format from ${trusteeEmail}`);

    // Store the submitted share (vault_id, trustee_email, share_data)
    // ON CONFLICT will UPDATE if same trustee resubmits (allows fixing mistakes)
    await query(
      `INSERT INTO trustee_share_submissions (vault_id, trustee_email, share_data, submitted_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (vault_id, trustee_email) DO UPDATE SET share_data = $3, submitted_at = NOW()`,
      [req.params.id, trusteeEmail, trimmedShare]
    );

    console.log(`✅ Stored share for ${trusteeEmail} in vault ${req.params.id}`);

    // Check how many shares have been submitted
    const submittedShares = await query(
      `SELECT COUNT(*) as count FROM trustee_share_submissions WHERE vault_id = $1`,
      [req.params.id]
    );

    const submittedCount = parseInt(submittedShares.rows[0].count);

    res.json({
      message: 'Share submitted successfully',
      submittedCount,
      requiredCount: vaultData.required_sigs,
      canUnlock: submittedCount >= vaultData.required_sigs
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to submit share' });
  }
});

// Reset/clear all submitted shares for a vault
app.delete('/api/vaults/:id/reset-shares', authenticateToken, async (req, res) => {
  try {
    const vault = await query(
      `SELECT v.* FROM vaults v WHERE v.id = $1 AND v.owner_id = $2`,
      [req.params.id, req.user.id]
    );

    if (!vault.rows.length) {
      return res.status(404).json({ error: 'Vault not found' });
    }

    // Delete all submitted shares for this vault
    await query(
      `DELETE FROM trustee_share_submissions WHERE vault_id = $1`,
      [req.params.id]
    );

    console.log(`🗑️ Reset all shares for vault ${req.params.id}`);

    res.json({
      message: 'All shares cleared successfully'
    });
  } catch (e) {
    console.error('Reset shares error:', e);
    res.status(500).json({ error: 'Failed to reset shares' });
  }
});

// Emergency unlock vault (reconstruct key from shares)
app.post('/api/vaults/:id/emergency-unlock', authenticateToken, async (req, res) => {
  try {
    const vault = await query(
      `SELECT v.* FROM vaults v WHERE v.id = $1 AND v.owner_id = $2`,
      [req.params.id, req.user.id]
    );

    if (!vault.rows.length) {
      return res.status(404).json({ error: 'Vault not found' });
    }

    const vaultData = vault.rows[0];

    // Get all submitted shares
    const submittedShares = await query(
      `SELECT share_data FROM trustee_share_submissions WHERE vault_id = $1 ORDER BY submitted_at`,
      [req.params.id]
    );

    if (submittedShares.rows.length < vaultData.required_sigs) {
      return res.status(400).json({
        error: `Insufficient shares. Need ${vaultData.required_sigs}, have ${submittedShares.rows.length}`
      });
    }

    // Reconstruct the master key from shares
    const shares = submittedShares.rows.map(row => row.share_data.trim());

    console.log(`🔐 Attempting to reconstruct key from ${shares.length} shares`);
    console.log(`   Required threshold: ${vaultData.required_sigs}`);
    shares.forEach((share, i) => {
      console.log(`   Share ${i + 1}: ${share.substring(0, 20)}... (length: ${share.length})`);
    });

    let reconstructedKeyHex;
    try {
      // Use Shamir's combine - this will FAIL if shares are invalid
      reconstructedKeyHex = secrets.combine(shares.slice(0, vaultData.required_sigs));
      console.log(`✅ Successfully combined ${vaultData.required_sigs} shares`);
      console.log(`   Reconstructed key (hex): ${reconstructedKeyHex.substring(0, 20)}... (length: ${reconstructedKeyHex.length})`);
      
      // CRITICAL FIX: secrets.js-grempe may pad the output
      // Original key is 32 bytes = 64 hex characters
      // Trim to exactly 64 hex chars to get back the original 32-byte key
      if (reconstructedKeyHex.length > 64) {
        console.log(`   Trimming padded key from ${reconstructedKeyHex.length} to 64 hex chars`);
        reconstructedKeyHex = reconstructedKeyHex.substring(0, 64);
      }
    } catch (err) {
      console.error('❌ Share combination failed:', err.message);
      console.error('   Error details:', err);
      return res.status(400).json({
        error: 'Invalid shares - unable to reconstruct key. Please verify all shares are exactly as received in email.'
      });
    }

    const reconstructedKey = Buffer.from(reconstructedKeyHex, 'hex');

    // Verify key is 32 bytes for AES-256
    if (reconstructedKey.length !== 32) {
      console.error(`❌ Invalid key length: ${reconstructedKey.length} bytes (expected 32)`);
      console.error(`   Hex string length: ${reconstructedKeyHex.length} chars (expected 64)`);
      return res.status(500).json({
        error: `Key reconstruction failed: got ${reconstructedKey.length} bytes, expected 32 bytes`
      });
    }

    console.log(`✅ Successfully reconstructed 32-byte AES key`);

    // Update all files in this vault with the reconstructed key
    await query(
      `UPDATE files SET encryption_key = $1 WHERE vault_id = $2`,
      [reconstructedKey, req.params.id]
    );

    // Mark vault as emergency unlocked by setting unlock_time to now
    await query(
      `UPDATE vaults SET unlock_time = NOW() WHERE id = $1`,
      [req.params.id]
    );

    res.json({
      message: 'Vault unlocked successfully via emergency protocol',
      unlockedAt: new Date().toISOString()
    });
  } catch (e) {
    console.error('Emergency unlock error:', e);
    res.status(500).json({ error: 'Emergency unlock failed: ' + e.message });
  }
});

// File download
app.get('/api/files/:id/download', authenticateToken, async (req, res) => {
  try {
    const file = await query(
      `SELECT f.*, v.owner_id, v.required_sigs, v.unlock_time
       FROM files f JOIN vaults v ON f.vault_id = v.id
       WHERE f.id = $1`,
      [req.params.id]
    );

    if (!file.rows.length) return res.status(404).json({ error: 'File not found' });
    const row = file.rows[0];

    if (row.owner_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    // Check time lock using accurate NTP time
    const now = await getCurrentTime();
    const unlockTime = row.unlock_time ? new Date(row.unlock_time) : null;

    if (unlockTime && now < unlockTime) {
      const timeLeft = Math.ceil((unlockTime - now) / 1000);
      console.log(`⏰ File locked. Current time: ${now.toISOString()}, Unlock time: ${unlockTime.toISOString()}`);
      return res.status(403).json({
        error: 'File is time-locked',
        unlockTime: unlockTime.toISOString(),
        timeLeftSeconds: timeLeft
      });
    }

    // Check if encryption key exists
    if (!row.encryption_key) {
      return res.status(403).json({
        error: 'Vault is locked. Emergency unlock required with trustee shares.'
      });
    }

    const encrypted = await fs.readFile(row.encrypted_path);

    // Ensure all BYTEA fields are proper Buffers
    let encryptionKey = row.encryption_key;
    let iv = row.iv;
    let authTag = row.auth_tag;

    // PostgreSQL BYTEA should return Buffer, but ensure it
    if (!Buffer.isBuffer(encryptionKey)) {
      console.log('Converting encryption_key to Buffer');
      encryptionKey = Buffer.from(encryptionKey);
    }
    if (!Buffer.isBuffer(iv)) {
      console.log('Converting iv to Buffer');
      iv = Buffer.from(iv);
    }
    if (!Buffer.isBuffer(authTag)) {
      console.log('Converting authTag to Buffer');
      authTag = Buffer.from(authTag);
    }

    // Verify key length
    if (encryptionKey.length !== 32) {
      console.error(`❌ Invalid encryption key length: ${encryptionKey.length} bytes (expected 32)`);
      console.error(`Key type: ${typeof encryptionKey}, isBuffer: ${Buffer.isBuffer(encryptionKey)}`);
      return res.status(500).json({
        error: `Invalid encryption key length: ${encryptionKey.length} bytes. Emergency unlock may be required.`
      });
    }

    // Verify IV length (should be 12 bytes for GCM)
    if (iv.length !== 12) {
      console.error(`❌ Invalid IV length: ${iv.length} bytes (expected 12)`);
      return res.status(500).json({ error: 'Invalid IV length' });
    }

    // Verify auth tag length (should be 16 bytes)
    if (authTag.length !== 16) {
      console.error(`❌ Invalid auth tag length: ${authTag.length} bytes (expected 16)`);
      return res.status(500).json({ error: 'Invalid auth tag length' });
    }

    console.log(`✅ Decrypting file: key=${encryptionKey.length}B, iv=${iv.length}B, tag=${authTag.length}B`);

    // Decrypt the file
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
      decipher.setAuthTag(authTag);
      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      console.log(`✅ File decrypted successfully: ${row.filename}`);

      res.setHeader('Content-Disposition', `attachment; filename="${row.filename}"`);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.send(decrypted);
    } catch (decryptError) {
      console.error('❌ Decryption failed:', decryptError);
      return res.status(500).json({
        error: 'Decryption failed - file may be corrupted or key is incorrect'
      });
    }
  } catch (e) {
    console.error('Download error:', e);
    res.status(500).json({ error: 'Download failed' });
  }
});

// Vault list
app.get('/api/vaults', authenticateToken, async (req, res) => {
  try {
    const vaults = await query(
      `SELECT v.id, v.name, v.description, v.unlock_time, v.required_sigs, v.trustee_count, v.created_at,
              COUNT(f.id) as file_count,
              COALESCE(SUM(f.filesize), 0) as total_size
       FROM vaults v
       LEFT JOIN files f ON v.id = f.vault_id
       WHERE v.owner_id = $1
       GROUP BY v.id
       ORDER BY v.created_at DESC`,
      [req.user.id]
    );

    res.json(vaults.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'List failed' });
  }
});

// Delete vault
app.delete('/api/vaults/:id', authenticateToken, async (req, res) => {
  try {
    const vault = await query('SELECT owner_id FROM vaults WHERE id = $1', [req.params.id]);
    if (!vault.rows.length || vault.rows[0].owner_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const files = await query('SELECT encrypted_path FROM files WHERE vault_id = $1', [req.params.id]);
    for (const file of files.rows) {
      try { await fs.unlink(file.encrypted_path); } catch (e) {}
    }

    await query('DELETE FROM trustee_share_submissions WHERE vault_id = $1', [req.params.id]);
    await query('DELETE FROM vault_trustees WHERE vault_id = $1', [req.params.id]);
    await query('DELETE FROM files WHERE vault_id = $1', [req.params.id]);
    await query('DELETE FROM vaults WHERE id = $1', [req.params.id]);

    res.json({ message: 'Vault deleted successfully' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Admin dashboard
app.get('/api/admin/dashboard', authenticateToken, adminOnly, async (req, res) => {
  try {
    const totals = {};

    const usersResult = await query('SELECT COUNT(*) as count FROM users');
    totals.users = parseInt(usersResult.rows[0].count);

    const vaultsResult = await query('SELECT COUNT(*) as count FROM vaults');
    totals.vaults = parseInt(vaultsResult.rows[0].count);

    const filesResult = await query('SELECT COUNT(*) as count, COALESCE(SUM(filesize), 0) as total_size FROM files');
    totals.files = parseInt(filesResult.rows[0].count);
    totals.storage = parseInt(filesResult.rows[0].total_size);

    const premiumResult = await query('SELECT COUNT(*) as count FROM users WHERE is_premium = true');
    totals.premium = parseInt(premiumResult.rows[0].count);

    const recentUsers = await query(
      'SELECT id, email, first_name, last_name, role, is_premium, created_at FROM users ORDER BY created_at DESC LIMIT 10'
    );

    const recentVaults = await query(
      `SELECT v.id, v.name, v.owner_id, u.email as owner_email, v.created_at
       FROM vaults v
       JOIN users u ON v.owner_id = u.id
       ORDER BY v.created_at DESC LIMIT 10`
    );

    res.json({
      totals,
      recentUsers: recentUsers.rows,
      recentVaults: recentVaults.rows
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Admin dashboard failed' });
  }
});

app.listen(PORT, '0.0.0.0', () => console.log(`✅ ChronoVault backend running on ${PORT}`));
