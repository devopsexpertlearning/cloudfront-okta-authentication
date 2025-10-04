// index.mjs
import { jwtVerify, createRemoteJWKSet } from 'jose';
import crypto from 'crypto';
import { URL, URLSearchParams } from 'url';

const OKTA_ISSUER = process.env.OKTA_ISSUER;
const OKTA_CLIENT_ID = process.env.OKTA_CLIENT_ID;
const OKTA_CLIENT_SECRET = process.env.OKTA_CLIENT_SECRET;
const CF_REDIRECT_PATH = '/_callback';
const COOKIE_SIGNING_KEY = process.env.COOKIE_SIGNING_KEY;
const COOKIE_NAME = process.env.COOKIE_NAME || 'cf_auth';
const STATE_COOKIE_NAME = process.env.STATE_COOKIE_NAME || 'okta_state';
const COOKIE_MAX_AGE_SECONDS = parseInt(process.env.COOKIE_MAX_AGE_SECONDS || '3600', 10);

const JWKS = createRemoteJWKSet(new URL(`${OKTA_ISSUER}/v1/keys`));

function buildSetCookie(name, value, opts = {}) {
  let c = `${name}=${value}`;
  if (opts.maxAge) c += `; Max-Age=${opts.maxAge}`;
  if (opts.path) c += `; Path=${opts.path}`;
  if (opts.httpOnly) c += '; HttpOnly';
  if (opts.secure) c += '; Secure';
  c += `; SameSite=${opts.sameSite || 'Lax'}`;
  return c;
}

function signSession(payloadJson) {
  const payloadB64 = Buffer.from(payloadJson).toString('base64url');
  const sig = crypto.createHmac('sha256', COOKIE_SIGNING_KEY).update(payloadB64).digest('base64url');
  return `${payloadB64}.${sig}`;
}

function verifySessionCookie(cookieValue) {
  try {
    const [payloadB64, sig] = cookieValue.split('.');
    if (!payloadB64 || !sig) return null;
    const expected = crypto.createHmac('sha256', COOKIE_SIGNING_KEY).update(payloadB64).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return null;
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return null;
    return payload;
  } catch { return null; }
}

function parseCookies(headers) {
  const cookieHeader = headers.cookie?.map(c => c.value).join('; ') || '';
  const cookies = {};
  cookieHeader.split(';').forEach(pair => {
    const [k, v] = pair.split('=').map(s => s.trim());
    if (k && v) cookies[k] = v;
  });
  return cookies;
}

function buildOktaAuthUrl(originalUrl, state) {
  const params = new URLSearchParams({
    client_id: OKTA_CLIENT_ID,
    response_type: 'code',
    scope: 'openid profile email',
    redirect_uri: `${originalUrl.origin}${CF_REDIRECT_PATH}`,
    state
  });
  return `${OKTA_ISSUER}/v1/authorize?${params.toString()}`;
}

async function exchangeCodeForToken(code) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: `${process.env.CF_REDIRECT_URI}`,
    client_id: OKTA_CLIENT_ID,
    client_secret: OKTA_CLIENT_SECRET
  });

  const res = await fetch(`${OKTA_ISSUER}/v1/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  if (!res.ok) throw new Error(`Token exchange failed: ${res.status}`);
  return res.json();
}

async function validateIdToken(idToken) {
  const { payload } = await jwtVerify(idToken, JWKS, {
    issuer: OKTA_ISSUER,
    audience: OKTA_CLIENT_ID
  });
  return payload;
}

// Lambda@Edge
export const handler = async (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers;
  const cookies = parseCookies(headers);

  const host = headers.host?.[0].value;
  const originalUrl = new URL(`https://${host}${request.uri}${request.querystring ? '?' + request.querystring : ''}`);

  if (cookies[COOKIE_NAME] && verifySessionCookie(cookies[COOKIE_NAME])) {
    return callback(null, request); // authenticated
  }

  if (request.uri === CF_REDIRECT_PATH) {
    const params = new URLSearchParams(request.querystring);
    const code = params.get('code');
    const state = params.get('state');

    if (!code || !state || cookies[STATE_COOKIE_NAME] !== state) {
      const newState = crypto.randomBytes(16).toString('hex');
      const oktaUrl = buildOktaAuthUrl(originalUrl, newState);
      const stateCookie = buildSetCookie(STATE_COOKIE_NAME, newState, { maxAge: 300, httpOnly: true, secure: true });
      return callback(null, { status: '302', headers: { location: [{ key: 'Location', value: oktaUrl }], 'set-cookie': [{ key: 'Set-Cookie', value: stateCookie }] } });
    }

    try {
      const tokenResp = await exchangeCodeForToken(code);
      const idPayload = await validateIdToken(tokenResp.id_token);

      const now = Math.floor(Date.now() / 1000);
      const session = { iat: now, exp: Math.min(now + COOKIE_MAX_AGE_SECONDS, idPayload.exp || now + COOKIE_MAX_AGE_SECONDS) };
      const signed = signSession(JSON.stringify(session));

      const sessionCookie = buildSetCookie(COOKIE_NAME, signed, { maxAge: session.exp - now, httpOnly: true, secure: true });
      const clearState = buildSetCookie(STATE_COOKIE_NAME, 'deleted', { maxAge: 0, httpOnly: true, secure: true });

      return callback(null, { status: '302', headers: { location: [{ key: 'Location', value: originalUrl.pathname }], 'set-cookie': [{ key: 'Set-Cookie', value: sessionCookie }, { key: 'Set-Cookie', value: clearState }] } });

    } catch {
      const newState = crypto.randomBytes(16).toString('hex');
      const oktaUrl = buildOktaAuthUrl(originalUrl, newState);
      const stateCookie = buildSetCookie(STATE_COOKIE_NAME, newState, { maxAge: 300, httpOnly: true, secure: true });
      return callback(null, { status: '302', headers: { location: [{ key: 'Location', value: oktaUrl }], 'set-cookie': [{ key: 'Set-Cookie', value: stateCookie }] } });
    }
  }

  const newState = crypto.randomBytes(16).toString('hex');
  const oktaUrl = buildOktaAuthUrl(originalUrl, newState);
  const stateCookie = buildSetCookie(STATE_COOKIE_NAME, newState, { maxAge: 300, httpOnly: true, secure: true });

  return callback(null, { status: '302', headers: { location: [{ key: 'Location', value: oktaUrl }], 'set-cookie': [{ key: 'Set-Cookie', value: stateCookie }] } });
};