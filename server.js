const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
// const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors'); // Import cors middleware
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors()); // Enable CORS for all routes

let privateKey;
let publicKey;
let kid;
let signingSecret;

// app.use('/api', createProxyMiddleware({
//   target: 'http://127.0.0.1:1234', // Replace with your target server
//   changeOrigin: true,
//   onProxyReq: (proxyReq, req, res) => {
//     // Add custom headers for CORS
//     proxyReq.setHeader('Access-Control-Allow-Origin', '*');
//     proxyReq.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
//     proxyReq.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
//   },
//   onProxyRes: (proxyRes, req, res) => {
//     // Add CORS headers to the response
//     proxyRes.headers['Access-Control-Allow-Origin'] = '*';
//     proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
//     proxyRes.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Authorization';
//   }
// }));

// Function to download keys and generate kid
const downloadKeys = async () => {
  try {
    const privateKeyResponse = await axios.get(process.env.PRIVATE_KEY_URL);
    privateKey = privateKeyResponse.data;
    const publicKeyResponse = await axios.get(process.env.PUBLIC_KEY_URL);
    publicKey = publicKeyResponse.data;

    // Generate kid from the public key
    kid = generateKid(publicKey);
  } catch (error) {
    console.error('Error downloading keys:', error);
  }
};

// Function to download signing secret
const downloadSigningSecret = async () => {
  try {
    const signingSecretResponse = await axios.get(process.env.SIGNING_SECRET_URL);
    signingSecret = signingSecretResponse.data.secret;
  } catch (error) {
    console.error('Error downloading signing secret:', error);
  }
};

// Generate kid from the public key (example function)
const generateKid = (publicKey) => {
  // Generate a hash of the publicKey to use as kid
  const hash = crypto.createHash('sha256');
  hash.update(publicKey);
  return hash.digest('hex');
};

// Download keys and generate kid at startup
downloadKeys();
downloadSigningSecret();

// Endpoint to retrieve kid
app.get('/get-kid', async (req, res) => {
  try {
    // Wait for keys to be downloaded if not already done
    if (!kid || !publicKey) {
      await downloadKeys();
    }

    res.json({ kid });
  } catch (error) {
    console.error('Error fetching kid:', error);
    res.status(500).json({ error: 'Failed to fetch kid' });
  }
});

// Endpoint to retrieve signing secret
app.get('/signing-secret', async (req, res) => {
  try {
    // Wait for signing secret to be downloaded if not already done
    if (!signingSecret) {
      await downloadSigningSecret();
    }

    res.json({ signingSecret });
  } catch (error) {
    console.error('Error fetching signing secret:', error);
    res.status(500).json({ error: 'Failed to fetch signing secret' });
  }
});

// Endpoint to generate JWT token
app.get('/generate-token', async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).send('Email is required');
  }

  // Wait for keys and signing secret to be downloaded if not already done
  if (!privateKey || !publicKey || !kid || !signingSecret) {
    await Promise.all([downloadKeys(), downloadSigningSecret()]);
  }

  const payload = {
    sub: email,
    aud: 'embeddables_token',
    iss: 'https://grove-rowan-armadillo.glitch.me/',
    scope: 'read:messages write:messages',
    iat: Math.floor(Date.now() / 1000) // Add issued at (iat) claim
  };

  const jwtOptions = {
    algorithm: 'RS256', // Use RSA SHA-256 for signing
    expiresIn: '1h',
    keyid: kid, // Include the kid in the JWT header
  };

  const token = jwt.sign(payload, privateKey, jwtOptions);
  res.json({ token });
});

// Endpoint to retrieve public key
app.get('/public-key', (req, res) => {
  res.type('text/plain');
  res.send(publicKey);
});

// Well-known configuration endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = `https://${req.get('host')}`; // Force HTTPS
  const wellKnownConfig = {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    response_types_supported: ['code', 'token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
  };
  res.json(wellKnownConfig);
});

// JWKS endpoint
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    // Wait for keys to be downloaded if not already done
    if (!publicKey) {
      await downloadKeys();
    }
    
    const jwk = {
      kty: 'RSA',
      kid,
      use: 'sig',
      alg: 'RS256',
      n: Buffer.from(publicKey.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, ''), 'base64')
        .toString('base64'),
      e: 'AQAB',
    };
    res.json({ keys: [jwk] });
  } catch (error) {
    console.error('Error fetching JWKS:', error);
    res.status(500).json({ error: 'Failed to fetch JWKS' });
  }
});

app.listen(port, () => {
  console.log(`JWT service running on port ${port}`);
});
