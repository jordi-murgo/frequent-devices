/**
 * Simple Web Server with API Proxy
 * Serves static files and proxies API requests to the backend server
 */
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');
const cors = require('cors');

// Configuration
const PORT = process.env.PORT || 8080;
const API_TARGET = process.env.API_URL || 'http://localhost:3000';
const STATIC_DIR = path.join(__dirname, '../frontend');

// Create Express app∫
const app = express();

// Enable CORS
app.use(cors());

// Configure API proxy
app.use('/api', createProxyMiddleware({
  target: API_TARGET,
  changeOrigin: true,
  pathRewrite: {
    '^/api': '/api', // Keep the /api prefix
  },
  logLevel: 'debug'
}));

// Serve static files from the parent directory
app.use(express.static(STATIC_DIR));

// Serve index.html for all routes (for SPA support)
app.get('*', (req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Web server running at http://localhost:${PORT}`);
  console.log(`Proxying API requests to ${API_TARGET}`);
  console.log(`Serving static files from ${STATIC_DIR}`);
});
