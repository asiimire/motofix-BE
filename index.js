// load env variables

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const AfricasTalking = require('africastalking');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Validate environment variables
const requiredEnvVars = ['AT_API_KEY', 'AT_USERNAME', 'FRONTEND_URL'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Initialize services
const AT = AfricasTalking({
  apiKey: process.env.AT_API_KEY,
  username: process.env.AT_USERNAME,
});
const sms = AT.SMS;

const dbPath = process.env.NODE_ENV === 'production' 
  ? path.join('/tmp', 'otp_database.db') 
  : 'otp_database.db';

const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) console.error('Database error:', err.message);
  db.run(`
    CREATE TABLE IF NOT EXISTS otps (
      phoneNumber TEXT PRIMARY KEY,
      otp TEXT NOT NULL,
      expiresAt INTEGER NOT NULL,
      createdAt INTEGER NOT NULL,
      attempts INTEGER DEFAULT 0,
      lastAttemptAt INTEGER
    )
  `);
});

const app = express();

// ========== CRITICAL CORS FIX ==========
const allowedOrigins = [
  'https://motofix-driver.vercel.app',
  'http://localhost:8080'
];

// Configure CORS to work with Vercel
// CORS Middleware
app.use((req, res, next) => {
  // Allow your frontend origin
  res.header('Access-Control-Allow-Origin', 'https://motofix-driver.vercel.app');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});
// Regular CORS middleware as fallback
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
// ========== END CORS FIX ==========

// Other middleware
app.use(express.json());

// Rate limiting middleware
const rateLimit = {};
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS = 5;

app.use((req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  
  if (!rateLimit[ip]) {
    rateLimit[ip] = { count: 1, startTime: now };
    return next();
  }
  
  if (now - rateLimit[ip].startTime > RATE_LIMIT_WINDOW) {
    rateLimit[ip] = { count: 1, startTime: now };
    return next();
  }
  
  if (rateLimit[ip].count >= MAX_REQUESTS) {
    return res.status(429).json({ 
      success: false, 
      message: 'Too many requests. Please try again later.' 
    });
  }
  
  rateLimit[ip].count++;
  next();
});

// Generate a 6-digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP endpoint
app.post('/api/send-otp', async (req, res) => {
  const { phoneNumber } = req.body;
  
  if (!phoneNumber) {
    return res.status(400).json({ 
      success: false, 
      message: 'Phone number is required' 
    });
  }

  // Validate phone number format
  if (!/^\+?\d{10,15}$/.test(phoneNumber)) {
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid phone number format' 
    });
  }

  const otp = generateOTP();
  const now = Date.now();
  const expiresAt = now + 5 * 60 * 1000; // OTP expires in 5 minutes

  try {
    // Check if recent OTP exists
    db.get(
      'SELECT createdAt FROM otps WHERE phoneNumber = ? AND createdAt > ?',
      [phoneNumber, now - 2 * 60 * 1000], // 2 minute cooldown
      (err, row) => {
        if (err) {
          console.error('Database error:', err.message);
          return res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
          });
        }

        if (row) {
          return res.status(429).json({ 
            success: false, 
            message: 'Please wait before requesting a new OTP' 
          });
        }

        // Send SMS
        sms.send({
          to: [phoneNumber],
          message: `Beloved, Your MOTOFIX verification code is: ${otp}`,
          from: '', // Default sender ID
        })
        .then(() => {
          // Store OTP in SQLite
          db.run(
            'INSERT OR REPLACE INTO otps (phoneNumber, otp, expiresAt, createdAt) VALUES (?, ?, ?, ?)',
            [phoneNumber, otp, expiresAt, now],
            (err) => {
              if (err) {
                console.error('Error storing OTP:', err.message);
                return res.status(500).json({ 
                  success: false, 
                  message: 'Failed to store OTP' 
                });
              }
              res.json({ 
                success: true, 
                message: `OTP sent to ${phoneNumber}` 
              });
            }
          );
        })
        .catch(error => {
          console.error('Error sending OTP:', error);
          res.status(500).json({ 
            success: false, 
            message: 'Failed to send OTP. Check credentials or credits.' 
          });
        });
      }
    );
  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'An unexpected error occurred' 
    });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', (req, res) => {
  const { phoneNumber, otp } = req.body;
  
  if (!phoneNumber || !otp) {
    return res.status(400).json({ 
      success: false, 
      message: 'Phone number and OTP are required' 
    });
  }

  db.get(
    'SELECT otp, expiresAt, attempts FROM otps WHERE phoneNumber = ?',
    [phoneNumber],
    (err, row) => {
      if (err) {
        console.error('Database error:', err.message);
        return res.status(500).json({ 
          success: false, 
          message: 'Internal server error' 
        });
      }

      if (!row) {
        return res.status(400).json({ 
          success: false, 
          message: 'OTP not found or expired' 
        });
      }

      const { otp: storedOTP, expiresAt, attempts } = row;
      const now = Date.now();

      // Check if OTP expired
      if (now > expiresAt) {
        db.run('DELETE FROM otps WHERE phoneNumber = ?', [phoneNumber]);
        return res.status(400).json({ 
          success: false, 
          message: 'OTP expired' 
        });
      }

      // Check attempt limit
      if (attempts >= 3) {
        db.run('DELETE FROM otps WHERE phoneNumber = ?', [phoneNumber]);
        return res.status(400).json({ 
          success: false, 
          message: 'Too many attempts. Please request a new OTP.' 
        });
      }

      // Verify OTP
      if (otp === storedOTP) {
        db.run('DELETE FROM otps WHERE phoneNumber = ?', [phoneNumber]);
        return res.json({ 
          success: true, 
          message: 'OTP verified successfully' 
        });
      } else {
        // Increment attempt counter
        db.run(
          'UPDATE otps SET attempts = attempts + 1, lastAttemptAt = ? WHERE phoneNumber = ?',
          [now, phoneNumber]
        );
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid OTP' 
        });
      }
    }
  );
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle shutdown gracefully
process.on('SIGTERM', () => {
  db.close();
  process.exit(0);
});