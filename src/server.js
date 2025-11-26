// Simple Node.js HTTP server to locally test Lambda@Edge Okta OIDC handler
// Usage: node server.js -------> Test with localhost

const http = require('http');
const url = require('url');
const { handler } = require('./index');

const PORT = process.env.PORT || 3000;

function toLambdaEvent(req, body) {
  const parsedUrl = url.parse(req.url, true);
  // Convert Node.js headers to CloudFront format
  const cfHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    cfHeaders[k.toLowerCase()] = [{ key: k, value: v }];
  }
  return {
    Records: [
      {
        cf: {
          request: {
            method: req.method,
            uri: parsedUrl.pathname,
            querystring: parsedUrl.query
              ? Object.entries(parsedUrl.query)
                  .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
                  .join('&')
              : '',
            headers: cfHeaders,
            body: body ? { data: Buffer.from(body).toString('base64'), encoding: 'base64' } : undefined,
          },
        },
      },
    ],
  };
}

function fromLambdaResponse(res, lambdaResp) {
  res.statusCode = parseInt(lambdaResp.status, 10) || 200;
  if (lambdaResp.headers) {
    for (const [k, arr] of Object.entries(lambdaResp.headers)) {
      for (const h of arr) {
        // Set-Cookie needs special handling
        if (k === 'set-cookie') {
          res.setHeader('Set-Cookie', arr.map(x => x.value));
          break;
        } else {
          res.setHeader(h.key, h.value);
        }
      }
    }
  }
  if (lambdaResp.body) {
    res.end(lambdaResp.body);
  } else if (lambdaResp.status && lambdaResp.status.startsWith('3') && lambdaResp.headers && lambdaResp.headers.location) {
    // Redirect with no body
    res.end();
  } else {
    res.end();
  }
}

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => (body += chunk));
  req.on('end', async () => {
    try {
      const event = toLambdaEvent(req, body);
      const lambdaResp = await handler(event);
      if (lambdaResp && lambdaResp.status) {
        fromLambdaResponse(res, lambdaResp);
      } else {
        // Proxy through (for static files, etc.)
        res.statusCode = 404;
        res.end('Not found');
      }
    } catch (err) {
      res.statusCode = 500;
      res.end('Internal server error: ' + err.message);
    }
  });
});

server.listen(PORT, () => {
  console.log(`Local test server running at http://localhost:${PORT}`);
  console.log('Test your OIDC flow in the browser!');
});
