'use strict';

// Import Node.js modules
const https = require('https');             // For making HTTPS requests
const querystring = require('querystring'); // For encoding/decoding URL query strings
const cookie = require('cookie');           // For parsing and serializing HTTP cookies
const crypto = require('crypto');           // For generating secure random values
const jwt = require('jsonwebtoken');        // For signing and verifying JWT tokens

// ======= HARD-CODED PARAMETERS FOR TESTING =======
const PARAMETERS = {
    JWT_SECRET: 'f8b3c1d2e4a5f6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1', // Secret key for JWT signing; replace with secure value
    OKTA_CLIENT_ID: 'YOUR-OKTA-CLIENT-ID',        // Your Okta application client ID
    OKTA_CLIENT_SECRET: 'YOUR-OKTA-CLIENT-SECRET',// Your Okta application client secret
    OKTA_DOMAIN: 'okta.devopsexpert.work.gd',     // Your Okta domain
    OKTA_TIMEOUT_MS: 5000,                        // Timeout for Okta HTTP requests
    AUTH_COOKIE_NAME: 'okta_auth',                // Name of the authentication cookie
    AUTH_COOKIE_TTL_SEC: '3600'                   // Authentication cookie lifetime in seconds (1 hour)
};

// Endpoint for login redirects (should match Okta app settings)
const LOGIN_ENDPOINT = '/authorization-code/callback';

// ====== UTILITY FUNCTIONS ======

// Extract and verify authentication JWT from request headers
async function getAuth(headers) {
    if (!headers.cookie) return null; // No cookies present
    for (const c of headers.cookie) {
        const cookies = cookie.parse(c.value); // Parse cookie string into key-value pairs
        if (PARAMETERS.AUTH_COOKIE_NAME in cookies) {
            try {
                return jwt.verify(cookies[PARAMETERS.AUTH_COOKIE_NAME], PARAMETERS.JWT_SECRET); // Verify JWT
            } catch {
                return null; // Invalid or expired JWT
            }
        }
    }
    return null; // Authentication cookie not found
}

// Generate a signed authentication cookie with JWT
async function generateAuthCookie(idToken) {
    const token = jwt.sign({ idToken }, PARAMETERS.JWT_SECRET, {
        algorithm: 'HS256',                               // HMAC SHA-256 algorithm
        expiresIn: parseInt(PARAMETERS.AUTH_COOKIE_TTL_SEC) // Set expiration time
    });
    // Return cookie string with security attributes
    return `${PARAMETERS.AUTH_COOKIE_NAME}=${token}; Secure; HttpOnly; SameSite=Lax`;
}

// Generate redirect response to Okta login page
function generateLoginRedirect(lambdaHost) {
    const nonce = crypto.randomBytes(32).toString('hex'); // Generate random nonce
    const location = `https://${PARAMETERS.OKTA_DOMAIN}/oauth2/v1/authorize?` +
        `client_id=${PARAMETERS.OKTA_CLIENT_ID}` +
        `&redirect_uri=https://${lambdaHost}${LOGIN_ENDPOINT}` +
        `&response_type=code&response_mode=query&scope=openid` +
        `&nonce=${nonce}&state=none`; // Build Okta authorization URL

    return {
        status: '302', // HTTP redirect
        statusDescription: 'Found',
        headers: { location: [{ key: 'Location', value: location }] }
    };
}

// Generate response for successful login (set cookie and redirect)
async function generateLoginSuccess(idToken) {
    return {
        status: '302', // HTTP redirect to main page
        statusDescription: 'Found',
        headers: {
            location: [{ key: 'Location', value: '/index.html' }], // Redirect target
            'set-cookie': [{ key: 'Set-Cookie', value: await generateAuthCookie(idToken) }] // Set auth cookie
        }
    };
}

// Exchange authorization code from Okta for tokens
function getOktaTokens(authCode, lambdaHost) {
    return new Promise((resolve) => {
        const postData = querystring.stringify({
            grant_type: 'authorization_code',             // OAuth2 grant type
            code: authCode,                                // Code received from Okta
            redirect_uri: `https://${lambdaHost}${LOGIN_ENDPOINT}` // Redirect URI
        });

        const options = {
            hostname: PARAMETERS.OKTA_DOMAIN,              // Okta server
            path: '/oauth2/v1/token',                      // Token endpoint
            method: 'POST',
            auth: `${PARAMETERS.OKTA_CLIENT_ID}:${PARAMETERS.OKTA_CLIENT_SECRET}`, // Basic auth
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: PARAMETERS.OKTA_TIMEOUT_MS           // Request timeout
        };

        const req = https.request(options, res => {
            let data = '';
            res.on('data', chunk => data += chunk);       // Collect response chunks
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);        // Parse JSON response
                    if (json.id_token) resolve(json);     // Return tokens if successful
                    else resolve(null);                   // No id_token, failure
                } catch {
                    resolve(null);                        // JSON parse error
                }
            });
        });

        req.on('error', () => resolve(null));             // Handle request errors
        req.write(postData);                               // Send POST body
        req.end();                                         // Finish request
    });
}

// ====== LAMBDA@EDGE HANDLER ======
exports.handler = async (event, context, callback) => {
    const request = event.Records[0].cf.request;        // CloudFront request object
    const headers = request.headers;                    // Extract headers
    const lambdaHost = headers.host[0].value;           // Get host from headers
    const queryParams = querystring.parse(request.querystring); // Parse query string

    const auth = await getAuth(headers);                // Check if user is authenticated

    if (auth) {
        if (request.uri === LOGIN_ENDPOINT) {
            // Authenticated user accessing login page -> redirect to main page
            callback(null, await generateLoginSuccess(auth.idToken));
        } else {
            // Authenticated user accessing other page -> allow request
            callback(null, request);
        }
    } else if (request.uri === LOGIN_ENDPOINT) {
        if (queryParams.code) {
            // Login endpoint with auth code -> exchange code for tokens
            const tokens = await getOktaTokens(queryParams.code, lambdaHost);
            if (tokens && tokens.id_token) {
                callback(null, await generateLoginSuccess(tokens.id_token));
            } else {
                // Failed token exchange -> unauthorized response
                callback(null, {
                    status: '401',
                    statusDescription: 'Unauthorized',
                    body: '<h1>401 Unauthorized</h1>'
                });
            }
        } else {
            // Login endpoint without code -> redirect to Okta login
            callback(null, generateLoginRedirect(lambdaHost));
        }
    } else {
        // Unauthenticated user accessing other page -> redirect to Okta login
        callback(null, generateLoginRedirect(lambdaHost));
    }
};
