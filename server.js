// A Node.js server for Zoom validation with multiple auth options
// Load environment variables
require('dotenv').config();

const http = require('http');
const crypto = require('crypto');
const url = require('url');

// Configuration from environment variables
const PORT = process.env.PORT || 3000;
const VERIFICATION_TOKEN = process.env.ZOOM_VERIFICATION_TOKEN || '';

// Basic auth credentials
const AUTH_USERNAME = process.env.BASIC_AUTH_USERNAME || '';
const AUTH_PASSWORD = process.env.BASIC_AUTH_PASSWORD || '';

// Custom header settings
const CUSTOM_HEADER_NAME = process.env.CUSTOM_HEADER_NAME || '';
const CUSTOM_HEADER_VALUE = process.env.CUSTOM_HEADER_VALUE || '';

// Create server
http.createServer((req, res) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url}`);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  
  // Log request details for debugging
  const parsedUrl = url.parse(req.url, true);
  console.log('Path:', parsedUrl.pathname);
  console.log('Query:', parsedUrl.query);
  
  // Check for Basic Auth if credentials are configured
  if (AUTH_USERNAME && AUTH_PASSWORD && req.headers.authorization) {
    console.log('Basic Auth enabled and Authorization header present');
    if (req.headers.authorization.startsWith('Basic ')) {
      const base64Credentials = req.headers.authorization.split(' ')[1];
      const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
      const [username, password] = credentials.split(':');
      
      console.log(`Basic Auth: User ${username}`);
      
      if (username !== AUTH_USERNAME || password !== AUTH_PASSWORD) {
        console.log('Basic auth failed');
        res.writeHead(401, { 
          'WWW-Authenticate': 'Basic',
          'Content-Type': 'application/json'
        });
        res.end(JSON.stringify({ error: 'Unauthorized: Invalid credentials' }));
        return;
      }
      console.log('Basic auth successful');
    }
  }
  
  // Check for Custom Header Auth if configured
  if (CUSTOM_HEADER_NAME && CUSTOM_HEADER_VALUE) {
    const headerName = CUSTOM_HEADER_NAME.toLowerCase();
    if (headerName in req.headers) {
      console.log(`Custom header ${CUSTOM_HEADER_NAME} present`);
      const headerValue = req.headers[headerName];
      
      if (headerValue !== CUSTOM_HEADER_VALUE) {
        console.log('Custom header auth failed');
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Invalid header token' }));
        return;
      }
      console.log('Custom header auth successful');
    }
  }
  
  // Only process POST requests
  if (req.method === 'POST') {
    let body = '';
    
    // Collect request body
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    // Process request when body is complete
    req.on('end', () => {
      console.log('Request body:', body);
      
      try {
        // Try to parse as JSON
        const requestData = JSON.parse(body);
        
        // Check if it's a validation request
        if (requestData.event === 'endpoint.url_validation' && requestData.payload && requestData.payload.plainToken) {
          const plainToken = requestData.payload.plainToken;
          console.log(`Plain token: ${plainToken}`);
          console.log(`Verification token: ${VERIFICATION_TOKEN ? VERIFICATION_TOKEN.substring(0, 5) + '...' : 'Not set'}`);
          
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
          console.log('Sent validation response:', JSON.stringify(responseData));
        } else {
          // Handle other webhook events
          console.log('Regular webhook event received:', requestData.event);
          
          // Process the webhook event (recording.completed, etc.)
          if (requestData.event === 'recording.completed' && requestData.payload && requestData.payload.object) {
            console.log('Recording completed webhook received');
            console.log('Meeting topic:', requestData.payload.object.topic);
            console.log('Recording files:', JSON.stringify(requestData.payload.object.recording_files || []));
            
            // Here you would normally process the recording
            // For now, just acknowledge receipt
          }
          
          // Send response
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ 
            message: 'Webhook received',
            event: requestData.event || 'unknown'
          }));
        }
      } catch (error) {
        // Error parsing request
        console.error('Error:', error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request format' }));
      }
    });
  } else if (req.method === 'GET') {
    // Handle GET requests with a simple response
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      message: 'Zoom Webhook Server', 
      status: 'running',
      timestamp: new Date().toISOString()
    }));
  } else {
    // Method not allowed
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
  }
}).listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Verification token: ${VERIFICATION_TOKEN ? 'Configured' : 'NOT CONFIGURED'}`);
  console.log(`Basic Auth: ${AUTH_USERNAME && AUTH_PASSWORD ? 'Enabled' : 'Disabled'}`);
  console.log(`Custom Header: ${CUSTOM_HEADER_NAME && CUSTOM_HEADER_VALUE ? 'Enabled' : 'Disabled'}`);
  console.log('Ready for Zoom webhook requests');
});