Project Structure
src/
│   └─ index.mjs      <-- your Lambda@Edge code (the optimized version I gave)
│
├─ package.json
└─ build.js           <-- esbuild build script


---

2️⃣ package.json

Minimal dependencies:

{
  "name": "lambda-okta-auth",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "jose": "^4.17.1",
    "node-fetch": "^3.3.1"
  },
  "devDependencies": {
    "esbuild": "^0.19.0"
  }
}

jose → JWT verification

node-fetch → For fetch in Node 22 Lambda@Edge

esbuild → Bundler


Install dependencies:

npm install


---

3️⃣ Build Script (build.js)

import esbuild from 'esbuild';

esbuild.build({
  entryPoints: ['./src/index.mjs'],
  bundle: true,           // bundle all dependencies into single file
  platform: 'node',       // Node.js target
  target: 'node22',       // Node 22 Lambda@Edge
  outfile: 'dist/index.mjs',
  format: 'esm',          // ES Modules
  minify: true,           // minify to reduce size
  sourcemap: false,
  external: [],           // include all dependencies
}).then(() => {
  console.log('✅ Build completed. File: dist/index.mjs');
}).catch((err) => {
  console.error(err);
  process.exit(1);
});


---

4️⃣ Build the Bundle

node build.js

Output: dist/index.mjs

Size: usually <1 MB (with minification)

Ready to zip and upload to Lambda@Edge.



---

5️⃣ Zip for Deployment

cd dist
zip -r lambda-okta-auth.zip index.mjs

Upload lambda-okta-auth.zip to AWS Lambda.

Runtime: Node.js 22.x

Handler: index.handler



---

6️⃣ Lambda@Edge Attachment

CloudFront Event:

Origin Request → checks authentication before reaching your origin

Viewer Request → faster redirect but slightly more limited


Configure Environment Variables:

OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET

COOKIE_SIGNING_KEY, CF_REDIRECT_URI

Optional: COOKIE_NAME, STATE_COOKIE_NAME, COOKIE_MAX_AGE_SECONDS




---

✅ Benefits of this setup:

Single minified file <1 MB

Fast execution at CloudFront edge

Production-ready with secure cookies and JWT validation

JWKS caching and state validation for security

Easy to maintain, extend, and debug
