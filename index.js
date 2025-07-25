require('dotenv').config();
const express = require('express');
const cors = require('cors');
const AfricasTalking = require('africastalking');
const sqlite3 = require('sqlite3').verbose();

// Initialize Africa's Talking
const AT = AfricasTalking({
  apiKey: process.env.AT_API_KEY,
  username: process.env.AT_USERNAME,
});
const sms = AT.SMS;

// Initialize SQLite
const db = new sqlite3.Database('otp_database.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    // Create OTPs table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS otps (
        phoneNumber TEXT PRIMARY KEY,
        otp TEXT NOT NULL,
        expiresAt INTEGER NOT NULL
      )
    `);
  }
});

// Initialize Express
const app = express();
app.use(cors());
app.use(express.json());

// Generate a 6-digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP
app.post('/api/send-otp', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    return res.status(400).json({ success: false, message: 'Phone number is required' });
  }

  const otp = generateOTP();
  const expiresAt = Date.now() + 5 * 60 * 1000; // OTP expires in 5 minutes

  try {
    await sms.send({
      to: [phoneNumber],
      message: `Your MotoFix verification code is: ${otp}`,
      from: '', // Empty from field to use default sender ID "ATCOMM"
    });
    
    // Store OTP in SQLite
    db.run(
      'INSERT OR REPLACE INTO otps (phoneNumber, otp, expiresAt) VALUES (?, ?, ?)',
      [phoneNumber, otp, expiresAt],
      (err) => {
        if (err) {
          console.error('Error storing OTP:', err.message);
          return res.status(500).json({ success: false, message: 'Failed to store OTP' });
        }
        res.json({ success: true, message: `OTP sent to ${phoneNumber}` });
      }
    );
  } catch (error) {
    console.error('Error sending OTP:', error.message);
    res.status(500).json({ success: false, message: 'Failed to send OTP. Check credentials or credits.' });
  }
});

// Verify OTP
app.post('/api/verify-otp', (req, res) => {
  const { phoneNumber, otp } = req.body;
  if (!phoneNumber || !otp) {
    return res.status(400).json({ success: false, message: 'Phone number and OTP are required' });
  }

  db.get('SELECT otp, expiresAt FROM otps WHERE phoneNumber = ?', [phoneNumber], (err, row) => {
    if (err) {
      console.error('Database error:', err.message);
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }

    if (!row) {
      return res.status(400).json({ success: false, message: 'OTP not found or expired' });
    }

    const { otp: storedOTP, expiresAt } = row;
    if (Date.now() > expiresAt) {
      db.run('DELETE FROM otps WHERE phoneNumber = ?', [phoneNumber]);
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    if (otp === storedOTP) {
      db.run('DELETE FROM otps WHERE phoneNumber = ?', [phoneNumber]);
      return res.status(200).json({ success: true, message: 'OTP verified successfully' });
    } else {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});