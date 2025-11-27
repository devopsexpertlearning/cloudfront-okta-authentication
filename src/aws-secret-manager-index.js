'use strict';

const https = require('https');
const querystring = require('querystring');
const cookie = require('cookie');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

// ======= ENV + CONFIG HELPERS =======

function getRequiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

// Name of the secret in AWS Secrets Manager that holds the Okta client secret
// Example: SECRET_NAME = "aem/okta-auth-secret"
const SECRET_NAME = process.env.SECRET_NAME || 'aem/okta-auth-secret';

const PARAMETERS = {
  // Secrets for JWT signing (from env)
  JWT_SESSION_SECRET: process.env.JWT_SESSION_SECRET || '',
  JWT_STATE_SECRET: process.env.JWT_STATE_SECRET || '',

  // Okta – client ID from env, client secret from Secrets Manager
  OKTA_CLIENT_ID: process.env.OKTA_CLIENT_ID || '',
  OKTA_DOMAIN: process.env.OKTA_DOMAIN || '',
  OKTA_TIMEOUT_MS: parseInt(process.env.OKTA_TIMEOUT_MS || '5000', 10),

  // Cookies
  AUTH_COOKIE_NAME: process.env.AUTH_COOKIE_NAME || 'okta_auth',
  AUTH_COOKIE_TTL_SEC: parseInt(process.env.AUTH_COOKIE_TTL_SEC || '3600', 10),
  STATE_COOKIE_NAME: process.env.STATE_COOKIE_NAME || 'okta_auth_state',
  STATE_TTL_SEC: parseInt(process.env.STATE_TTL_SEC || '300', 10),

  // Optional: one fixed public URL. If not set, we derive from Host dynamically.
  // Example: PUBLIC_APP_URL=https://app.example.com
  PUBLIC_APP_URL: process.env.PUBLIC_APP_URL || null,

  // Issuer – strongly recommended to set explicitly:
  // OKTA_ISSUER=https://your-okta-domain.okta.com/oauth2/default
  OKTA_ISSUER: process.env.OKTA_ISSUER || null,
};

// OIDC endpoints / issuer
const LOGIN_ENDPOINT = '/callback';
const LOGOUT_ENDPOINT = '/logout';

const OKTA_ISSUER = PARAMETERS.OKTA_ISSUER ||
  `https://${PARAMETERS.OKTA_DOMAIN}`;

const OKTA_JWKS_PATH = '/oauth2/v1/keys';

// ======= SECRETS MANAGER (OKTA CLIENT SECRET) =======

let clientSecretCache = null;
const secretsClient = new SecretsManagerClient({ region: 'us-east-1' });

async function getClientSecret() {
  if (clientSecretCache) {
    return clientSecretCache;
  }

  const envSecret = process.env.OKTA_CLIENT_SECRET;
  if (envSecret) {
    clientSecretCache = envSecret;
    return clientSecretCache;
  }

  if (!SECRET_NAME) {
    throw new Error('SECRET_NAME env var is required to load Okta client secret from Secrets Manager');
  }

  try {
    const data = await secretsClient.send(new GetSecretValueCommand({ SecretId: SECRET_NAME }));

    if ('SecretString' in data) {
      let secretValue = data.SecretString;

      // Console "key/value" secrets are JSON; support multi-env structures as well
      if (typeof secretValue === 'string') {
        try {
          const parsed = JSON.parse(secretValue);
          if (parsed && typeof parsed === 'object') {
            secretValue = extractClientSecret(parsed);
          }
        } catch (err) {
          // Secret value is plain text instead of JSON; use as-is
        }
      }

      if (!secretValue || typeof secretValue !== 'string') {
        throw new Error('CLIENT_SECRET value missing or invalid in secret');
      }

      clientSecretCache = secretValue;
      return clientSecretCache;
    }

    throw new Error('SecretString not found in secret');
  } catch (err) {
    throw new Error(`Failed to retrieve client secret from Secrets Manager: ${err.message}`);
  }
}

function extractClientSecret(obj) {
  if (!obj || typeof obj !== 'object') return undefined;

  const explicit = obj.CLIENT_SECRET || obj.client_secret || obj.clientSecret;
  if (explicit && typeof explicit === 'string') {
    return explicit;
  }

  const desiredKey = process.env.OKTA_CLIENT_SECRET_KEY;
  if (desiredKey && typeof obj[desiredKey] === 'string') {
    return obj[desiredKey];
  }

  const preferredKeys = [
    'DEV_AEM_OKTA_CLIENT_SECRET'
  ];

  for (const key of preferredKeys) {
    if (typeof obj[key] === 'string') {
      return obj[key];
    }
  }

  const firstStringValue = Object.values(obj).find(v => typeof v === 'string');
  return firstStringValue;
}

// ======= SIMPLE IN-MEMORY JWKS CACHE =======

let jwksCache = {
  keys: null,
  fetchedAt: 0,
  ttlMs: 10 * 60 * 1000, // 10 minutes
};

function httpsGetJson(options, postData) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json);
        } catch (err) {
          reject(new Error(`Failed to parse JSON: ${err.message}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (postData) {
      req.write(postData);
    }

    req.end();
  });
}

async function getJwksKey(kid) {
  const now = Date.now();

  if (!jwksCache.keys || now - jwksCache.fetchedAt > jwksCache.ttlMs) {
    console.log('[JWKS] Fetching new JWKS from Okta');
    const options = {
      hostname: PARAMETERS.OKTA_DOMAIN,
      path: OKTA_JWKS_PATH,
      method: 'GET',
      timeout: PARAMETERS.OKTA_TIMEOUT_MS,
    };
    const jwks = await httpsGetJson(options);
    jwksCache.keys = jwks.keys || [];
    jwksCache.fetchedAt = now;
  }

  const key = jwksCache.keys.find(k => k.kid === kid);
  if (!key) throw new Error(`No JWKS key found for kid=${kid}`);

  if (key.x5c && key.x5c.length) {
    return `-----BEGIN CERTIFICATE-----\n${key.x5c[0].match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  } else if (key.n && key.e) {
    return jwkToPem(key);
  } else {
    throw new Error('JWKS key missing usable public key data (x5c or n/e)');
  }
}

// ======= HOST HANDLING (DYNAMIC, NO ALLOW-LIST) =======

function getHost(headers) {
  const hostHeader = headers['x-host-header']
    ? headers['x-host-header'][0].value
    : (headers.host && headers.host[0] && headers.host[0].value);

  if (!hostHeader) {
    throw new Error('Missing Host header');
  }

  return hostHeader.toLowerCase();
}

function getAppBaseUrl(lambdaHost) {
  if (PARAMETERS.PUBLIC_APP_URL) {
    // If you set PUBLIC_APP_URL, we force everything to that
    return PARAMETERS.PUBLIC_APP_URL.replace(/\/+$/, '');
  }
  // Otherwise, derive per-request from the Host header
  return `https://${lambdaHost}`;
}

// ======= COOKIE UTILITIES =======

function parseCookies(headers) {
  const allCookies = {};
  if (!headers.cookie) return allCookies;

  for (const c of headers.cookie) {
    Object.assign(allCookies, cookie.parse(c.value));
  }
  return allCookies;
}

function buildCookie(name, value, options = {}) {
  return cookie.serialize(name, value, {
    httpOnly: options.httpOnly !== false,
    secure: options.secure !== false,
    sameSite: options.sameSite || 'Lax',
    maxAge: options.maxAge,
    path: options.path || '/',
  });
}

// ======= SESSION (AUTH COOKIE) =======

async function generateAuthCookie(idTokenClaims) {
  const payload = {
    sub: idTokenClaims.sub,
    email: idTokenClaims.email,
    name: idTokenClaims.name,
    rawIdToken: idTokenClaims.__raw || undefined,
  };

  const token = jwt.sign(payload, PARAMETERS.JWT_SESSION_SECRET, {
    algorithm: 'HS256',
    expiresIn: PARAMETERS.AUTH_COOKIE_TTL_SEC,
  });

  return buildCookie(PARAMETERS.AUTH_COOKIE_NAME, token, {
    maxAge: PARAMETERS.AUTH_COOKIE_TTL_SEC,
    path: '/',
    sameSite: 'Lax',
    secure: true,
  });
}

function clearAuthCookie() {
  return buildCookie(PARAMETERS.AUTH_COOKIE_NAME, '', {
    maxAge: 0,
    path: '/',
    sameSite: 'Lax',
    secure: true,
  });
}

async function getAuth(headers) {
  const cookies = parseCookies(headers);
  const raw = cookies[PARAMETERS.AUTH_COOKIE_NAME];
  if (!raw) return null;

  try {
    const decoded = jwt.verify(raw, PARAMETERS.JWT_SESSION_SECRET);
    return decoded;
  } catch (err) {
    console.warn('[AUTH] Failed to verify session cookie:', err.message);
    return null;
  }
}

// ======= STATE + NONCE HANDLING =======

async function generateStateCookie() {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(32).toString('hex');

  const token = jwt.sign({ state, nonce }, PARAMETERS.JWT_STATE_SECRET, {
    algorithm: 'HS256',
    expiresIn: PARAMETERS.STATE_TTL_SEC,
  });

  const cookieStr = buildCookie(PARAMETERS.STATE_COOKIE_NAME, token, {
    maxAge: PARAMETERS.STATE_TTL_SEC,
    path: LOGIN_ENDPOINT,
    sameSite: 'Lax',
    secure: true,
  });

  return { state, nonce, cookieStr };
}

async function getStateAndNonce(headers) {
  const cookies = parseCookies(headers);
  const raw = cookies[PARAMETERS.STATE_COOKIE_NAME];
  if (!raw) throw new Error('Missing state cookie');

  try {
    const decoded = jwt.verify(raw, PARAMETERS.JWT_STATE_SECRET);
    return decoded;
  } catch (err) {
    throw new Error('Invalid or expired state cookie');
  }
}

function clearStateCookie() {
  return buildCookie(PARAMETERS.STATE_COOKIE_NAME, '', {
    maxAge: 0,
    path: LOGIN_ENDPOINT,
    sameSite: 'Lax',
    secure: true,
  });
}

// ======= ID TOKEN VERIFICATION =======

async function verifyIdToken(idToken, expectedNonce) {
  const decodedHeader = jwt.decode(idToken, { complete: true });
  if (!decodedHeader || !decodedHeader.header) {
    throw new Error('Failed to decode id_token header');
  }

  const { kid } = decodedHeader.header;
  if (!kid) {
    throw new Error('id_token missing kid header');
  }

  const cert = await getJwksKey(kid);

  const claims = jwt.verify(idToken, cert, {
    algorithms: ['RS256'],
    issuer: OKTA_ISSUER,
    audience: PARAMETERS.OKTA_CLIENT_ID,
    clockTolerance: 300, // 5 minutes clock skew
  });

  if (!claims.nonce || claims.nonce !== expectedNonce) {
    throw new Error('Nonce mismatch in id_token');
  }

  claims.__raw = idToken;

  return claims;
}

// ======= OKTA TOKEN EXCHANGE =======

async function getOktaTokens(authCode, appBaseUrl) {
  const redirectUri = `${appBaseUrl}${LOGIN_ENDPOINT}`;
  const oktaClientSecret = await getClientSecret();

  const postData = querystring.stringify({
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: redirectUri,
  });

  const options = {
    hostname: PARAMETERS.OKTA_DOMAIN,
    path: '/oauth2/v1/token',
    method: 'POST',
    auth: `${PARAMETERS.OKTA_CLIENT_ID}:${oktaClientSecret}`,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: PARAMETERS.OKTA_TIMEOUT_MS,
  };

  try {
    const json = await httpsGetJson(options, postData);
    if (!json.id_token) {
      console.warn('[OKTA] Token response missing id_token:', JSON.stringify(json));
      return null;
    }
    return json;
  } catch (err) {
    console.error('[OKTA] Error fetching tokens:', err.message);
    return null;
  }
}

// ======= RESPONSES =======

function redirect(location, extraHeaders = {}) {
  return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: location }],
      ...extraHeaders,
    },
  };
}

function htmlResponse(status, statusDescription, body) {
  return {
    status: String(status),
    statusDescription,
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'text/html; charset=utf-8' }],
    },
    body,
  };
}

// ======= LOGIN REDIRECT =======

async function generateLoginRedirect(appBaseUrl) {
  const { state, nonce, cookieStr } = await generateStateCookie();
  const redirectUri = `${appBaseUrl}${LOGIN_ENDPOINT}`;

  const location =
    `https://${PARAMETERS.OKTA_DOMAIN}/oauth2/v1/authorize?` +
    `client_id=${encodeURIComponent(PARAMETERS.OKTA_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&response_mode=query` +
    `&scope=${encodeURIComponent('openid email profile')}` +
    `&nonce=${encodeURIComponent(nonce)}` +
    `&state=${encodeURIComponent(state)}`;

  return redirect(location, {
    'set-cookie': [{ key: 'Set-Cookie', value: cookieStr }],
  });
}

// ======= LOGIN SUCCESS =======

async function generateLoginSuccess(idTokenClaims, appBaseUrl) {
  const authCookie = await generateAuthCookie(idTokenClaims);
  const clearState = clearStateCookie();

  return redirect(`${appBaseUrl}/`, {
    'set-cookie': [
      { key: 'Set-Cookie', value: authCookie },
      { key: 'Set-Cookie', value: clearState },
    ],
  });
}

// ======= LOGOUT =======

async function handleLogout(auth, appBaseUrl) {
  const clearAuth = clearAuthCookie();
  const clearState = clearStateCookie();

  let location = `${appBaseUrl}/`;

  if (auth && auth.rawIdToken) {
    const base = `https://${PARAMETERS.OKTA_DOMAIN}/oauth2/v1/logout`;
    const qs = querystring.stringify({
      id_token_hint: auth.rawIdToken,
      post_logout_redirect_uri: location,
    });
    location = `${base}?${qs}`;
  }

  return redirect(location, {
    'set-cookie': [
      { key: 'Set-Cookie', value: clearAuth },
      { key: 'Set-Cookie', value: clearState },
    ],
  });
}

// ======= MAIN LAMBDA@EDGE HANDLER =======

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;
  const uri = request.uri;
  const queryParams = querystring.parse(request.querystring || '');

  let lambdaHost;
  let appBaseUrl;

  try {
    lambdaHost = getHost(headers);            // derive host (or x-host-header)
    appBaseUrl = getAppBaseUrl(lambdaHost);   // build https://host (or PUBLIC_APP_URL)
  } catch (err) {
    console.error('[ERROR] Host handling failed:', err.message);
    return htmlResponse(400, 'Bad Request', '<h1>400 Bad Request</h1><p>Invalid host.</p>');
  }

  try {
    const auth = await getAuth(headers);

    // LOGOUT
    if (uri === LOGOUT_ENDPOINT) {
      console.log('[REQUEST] Logout endpoint hit');
      return await handleLogout(auth, appBaseUrl);
    }

    // AUTHENTICATED FLOW
    if (auth) {
      if (uri === LOGIN_ENDPOINT) {
        console.log('[AUTH] Authenticated user hit /callback, redirecting to /');
        const authCookie = await generateAuthCookie(auth);
        const clearState = clearStateCookie();
        return redirect(`${appBaseUrl}/`, {
          'set-cookie': [
            { key: 'Set-Cookie', value: authCookie },
            { key: 'Set-Cookie', value: clearState },
          ],
        });
      }

      // Allow request through
      return request;
    }

    // UNAUTHENTICATED FLOW
    if (uri === LOGIN_ENDPOINT) {
      // Callback with code + state
      if (queryParams.code && queryParams.state) {
        console.log('[LOGIN] Processing callback with code and state');

        let stateCookie;
        try {
          stateCookie = await getStateAndNonce(headers);
        } catch (err) {
          console.warn('[LOGIN] State cookie error:', err.message);
          return htmlResponse(401, 'Unauthorized', '<h1>401 Unauthorized</h1><p>Invalid login state.</p>');
        }

        if (queryParams.state !== stateCookie.state) {
          console.warn('[LOGIN] State mismatch');
          return htmlResponse(401, 'Unauthorized', '<h1>401 Unauthorized</h1><p>Invalid login state.</p>');
        }

        const tokens = await getOktaTokens(queryParams.code, appBaseUrl);
        if (!tokens || !tokens.id_token) {
          return htmlResponse(401, 'Unauthorized', '<h1>401 Unauthorized</h1><p>Failed to exchange authorization code.</p>');
        }

        let idTokenClaims;
        try {
          idTokenClaims = await verifyIdToken(tokens.id_token, stateCookie.nonce);
        } catch (err) {
          console.error('[LOGIN] Failed to verify id_token:', err.message);
          return htmlResponse(401, 'Unauthorized', '<h1>401 Unauthorized</h1><p>Invalid ID token.</p>');
        }

        return await generateLoginSuccess(idTokenClaims, appBaseUrl);
      }

      // Initial /callback hit: redirect to Okta
      console.log('[LOGIN] Unauthenticated request to /callback, redirecting to Okta');
      return await generateLoginRedirect(appBaseUrl);
    }

    // Any other path for unauthenticated user -> redirect to /callback
    console.log('[AUTH] Unauthenticated request to', uri, 'redirecting to login');
    return redirect(`${appBaseUrl}${LOGIN_ENDPOINT}`);
  } catch (err) {
    console.error('[ERROR] Unexpected error in handler:', err);
    return htmlResponse(500, 'Internal Server Error', '<h1>500 Internal Server Error</h1><p>Please try again later.</p>');
  }
};
