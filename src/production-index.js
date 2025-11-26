'use strict';

  const https = require('https');
  const querystring = require('querystring');
  const cookie = require('cookie');
  const crypto = require('crypto');
  const jwt = require('jsonwebtoken');
  const jwkToPem = require('jwk-to-pem');

  // ======= CONFIG / PARAMETERS =======
  // In production, inject these via env vars or your deployment pipeline.
const PARAMETERS = {
  JWT_SECRET: process.env.JWT_SECRET || 'REPLACE_ME_WITH_STRONG_SECRET',
  OKTA_CLIENT_ID: process.env.OKTA_CLIENT_ID || 'YOUR-OKTA-CLIENT-ID',
  OKTA_CLIENT_SECRET: process.env.OKTA_CLIENT_SECRET || 'YOUR-OKTA-CLIENT-SECRET',
  OKTA_DOMAIN: process.env.OKTA_DOMAIN || 'okta.devopsexpert.work.gd',
  OKTA_TIMEOUT_MS: parseInt(process.env.OKTA_TIMEOUT_MS || '5000', 10),
  AUTH_COOKIE_NAME: process.env.AUTH_COOKIE_NAME || 'okta_auth',
  AUTH_COOKIE_TTL_SEC: parseInt(process.env.AUTH_COOKIE_TTL_SEC || '3600', 10),
  STATE_COOKIE_NAME: process.env.STATE_COOKIE_NAME || 'okta_auth_state',
  STATE_TTL_SEC: parseInt(process.env.STATE_TTL_SEC || '300', 10), // 5 minutes
};

  // OIDC endpoints / issuer
  const LOGIN_ENDPOINT = '/login';
  const LOGOUT_ENDPOINT = '/logout';
  const OKTA_ISSUER = `https://${PARAMETERS.OKTA_DOMAIN}`; // adjust if using custom /oauth2/default, etc.
  const OKTA_JWKS_PATH = '/oauth2/v1/keys';

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
  // Fetch JWKS if cache is empty or expired
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
    // Traditional cert path
    return `-----BEGIN CERTIFICATE-----\n${key.x5c[0].match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  } else if (key.n && key.e) {
    // Build PEM from modulus & exponent
    return jwkToPem(key);  // returns a PEM-formatted string
  } else {
    throw new Error('JWKS key missing usable public key data (x5c or n/e)');
  }
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
      secure: options.secure !== false, // For Lambda@Edge, always secure
      sameSite: options.sameSite || 'Lax',
      maxAge: options.maxAge,
      path: options.path || '/',
      // domain: options.domain, // Optional: set if you need a specific domain
    });
  }

  // ======= SESSION (AUTH COOKIE) =======
  async function generateAuthCookie(idTokenClaims) {
    // Store only what you need. Here we use a subset of claims.
    const payload = {
      sub: idTokenClaims.sub,
      email: idTokenClaims.email,
      name: idTokenClaims.name,
      // Keep full raw id_token if you want to support Okta logout with id_token_hint:
      rawIdToken: idTokenClaims.__raw || undefined,
    };

    const token = jwt.sign(payload, PARAMETERS.JWT_SECRET, {
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
      const decoded = jwt.verify(raw, PARAMETERS.JWT_SECRET);
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

    const token = jwt.sign({ state, nonce }, PARAMETERS.JWT_SECRET, {
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
      const decoded = jwt.verify(raw, PARAMETERS.JWT_SECRET);
      return decoded; // { state, nonce, iat, exp }
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

    let cert;
    try {
      cert = await getJwksKey(kid);
    } catch (err) {
      throw err;
    }

    let claims;
    try {
      claims = jwt.verify(idToken, cert, {
        algorithms: ['RS256'],
        issuer: OKTA_ISSUER,
        audience: PARAMETERS.OKTA_CLIENT_ID,
        clockTolerance: 300 // allow 5 minutes of clock skew
      });
    } catch (err) {
      throw err;
    }

    // Nonce check
    if (!claims.nonce || claims.nonce !== expectedNonce) {
      throw new Error('Nonce mismatch in id_token');
    }

    // Attach raw token (optional, for logout)
    claims.__raw = idToken;

    return claims;
  }

  // ======= OKTA TOKEN EXCHANGE =======
  async function getOktaTokens(authCode, lambdaHost) {
    const postData = querystring.stringify({
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: `https://${lambdaHost}${LOGIN_ENDPOINT}`,
    });

    const options = {
      hostname: PARAMETERS.OKTA_DOMAIN,
      path: '/oauth2/v1/token',
      method: 'POST',
      auth: `${PARAMETERS.OKTA_CLIENT_ID}:${PARAMETERS.OKTA_CLIENT_SECRET}`,
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
  async function generateLoginRedirect(lambdaHost, headers) {
    const { state, nonce, cookieStr } = await generateStateCookie();

    const location =
      `https://${PARAMETERS.OKTA_DOMAIN}/oauth2/v1/authorize?` +
      `client_id=${encodeURIComponent(PARAMETERS.OKTA_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(`https://${lambdaHost}${LOGIN_ENDPOINT}`)}` +
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
  async function generateLoginSuccess(idTokenClaims) {
    const authCookie = await generateAuthCookie(idTokenClaims);
    const clearState = clearStateCookie();

    return redirect('/', {
      'set-cookie': [
        { key: 'Set-Cookie', value: authCookie },
        { key: 'Set-Cookie', value: clearState },
      ],
    });
  }

  // ======= LOGOUT =======
  async function handleLogout(auth) {
    const clearAuth = clearAuthCookie();
    const clearState = clearStateCookie();

    // Optional: redirect to Okta logout endpoint if you want to kill Okta session as well.
    // If you kept rawIdToken, you could use id_token_hint here.
    const location = '/';

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
    // Use x-host-header if present (custom domain), else fallback to CloudFront host
    const lambdaHost = headers['x-host-header']
      ? headers['x-host-header'][0].value
      : headers.host[0].value;
    const uri = request.uri;
    const queryParams = querystring.parse(request.querystring || '');

    try {
      const auth = await getAuth(headers);

      // ===== LOGOUT ENDPOINT =====
      if (uri === LOGOUT_ENDPOINT) {
        console.log('[REQUEST] Logout endpoint hit');
        return await handleLogout(auth);
      }

      // ===== AUTHENTICATED USER =====
      if (auth) {
        if (uri === LOGIN_ENDPOINT) {
          // Already logged in; just redirect them home
          console.log('[AUTH] Authenticated user hit /login, redirecting to /');
          const authCookie = await generateAuthCookie(auth);
          const clearState = clearStateCookie();
          return redirect('/', {
            'set-cookie': [
              { key: 'Set-Cookie', value: authCookie },
              { key: 'Set-Cookie', value: clearState },
            ],
          });
        }

        // Authenticated, non-login URIs: allow request through
        return request;
      }

      // ===== UNAUTHENTICATED USER =====

      if (uri === LOGIN_ENDPOINT) {
        // Step 2 of OIDC: callback with authorization code
        if (queryParams.code && queryParams.state) {
          console.log('[LOGIN] Processing callback with code and state');

          let stateCookie;
          try {
            stateCookie = await getStateAndNonce(headers); // { state, nonce }
          } catch (err) {
            console.warn('[LOGIN] State cookie error:', err.message);
            return htmlResponse(401, 'Unauthorized', '<h1>401 Unauthorized</h1><p>Invalid login state.</p>');
          }

          if (queryParams.state !== stateCookie.state) {
            console.warn('[LOGIN] State mismatch');
            return htmlResponse(401, 'Unauthorized', '<h1>401 Unauthorized</h1><p>Invalid login state.</p>');
          }

          const tokens = await getOktaTokens(queryParams.code, lambdaHost);
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

          return await generateLoginSuccess(idTokenClaims);
        }

        // Initial /login hit: redirect to Okta login with state+nonce
        console.log('[LOGIN] Unauthenticated request to /login, redirecting to Okta');
        return await generateLoginRedirect(lambdaHost, headers);
      }

      // Any other path for unauthenticated user -> redirect to /login (which will redirect to Okta)
      console.log('[AUTH] Unauthenticated request to', uri, 'redirecting to login');
      return redirect(`https://${lambdaHost}${LOGIN_ENDPOINT}`);
    } catch (err) {
      console.error('[ERROR] Unexpected error in handler:', err);
      return htmlResponse(500, 'Internal Server Error', '<h1>500 Internal Server Error</h1><p>Please try again later.</p>');
    }
  };
