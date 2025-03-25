// A super simple Node.js server for Zoom validation
// No TypeScript, no Express, just plain Node.js
// Run with: node server.js

const http = require('http');
const crypto = require('crypto');

// Configuration
const PORT = process.env.PORT || 3000;
const VERIFICATION_TOKEN = process.env.ZOOM_VERIFICATION_TOKEN || '';

// Create server
http.createServer((req, res) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  
  // Only care about POST requests
  if (req.method === 'POST') {
    let body = '';
    
    // Collect request body
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    // Process request when body is complete
    req.on('end', () => {
      try {
        // Try to parse as JSON
        const requestData = JSON.parse(body);
        console.log('Request body:', JSON.stringify(requestData, null, 2));
        
        // Check if it's a validation request
        if (requestData.event === 'endpoint.url_validation' && requestData.payload && requestData.payload.plainToken) {
          const plainToken = requestData.payload.plainToken;
          console.log(`Plain token: ${plainToken}`);
          console.log(`Verification token: ${VERIFICATION_TOKEN.substring(0, 5)}...`);
          
          // Calculate encrypted token
          const hashAlgorithm = crypto.createHmac('sha256', VERIFICATION_TOKEN);
          const encryptedToken = hashAlgorithm.update(plainToken).digest('hex');
          console.log(`Encrypted token: ${encryptedToken}`);
          
          // Prepare response
          const responseData = {
            plainToken: plainToken,
            encryptedToken: encryptedToken
          };
          
          // Send response
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(responseData));
          console.log('Sent validation response');
        } else {
          // Not a validation request
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Not a validation request' }));
        }
      } catch (error) {
        // Error parsing request
        console.error('Error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
  } else {
    // Handle GET requests with a simple response
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      message: 'Simple Zoom validation server', 
      status: 'running',
      usage: 'Send POST requests for Zoom webhook validation' 
    }));
  }
}).listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
  console.log(`Using verification token: ${VERIFICATION_TOKEN.substring(0, 5)}...`);
  console.log('Ready for Zoom webhook validation requests');
});