# Lambda@Edge Okta Authentication

A lightweight, production-ready Lambda@Edge function for securing CloudFront with **Okta authentication**.
Optimized for **Node.js 22 runtime** with ESBuild bundling.

---

## 📂 Project Structure

```
src/
  └─ index.js      <-- your Lambda@Edge code (optimized)
```

---

## 📦 package.json

Minimal dependencies:

```bash
# Run this

npm init -y

```

* **josewebtoken** → JWT verification
* **cookie** → Fetch cookie


Install dependencies:

```bash

npm install cookie jsonwebtoken

#For production-index.js
npm install cookie jsonwebtoken jwk-to-pem

```

---

## ⚡ Make Zip file

```bash

zip -r okta-auth.zip index.js node_modules ;


```

---


Upload `okta-auth.zip` to **AWS Lambda**.

* **Runtime:** Node.js 22.x
* **Handler:** `index.handler`

---

## 🌍 Lambda@Edge Attachment

Attach the Lambda@Edge function to CloudFront events:

* **Origin Request** → checks authentication before reaching origin
* **Viewer Request** → faster redirect but slightly more limited

### Environment Variables

Required:

* `JWT_SECRET`
* `OKTA_CLIENT_ID`
* `OKTA_CLIENT_SECRET`
* `OKTA_DOMAIN`
* `OKTA_TIMEOUT_MS`
* `AUTH_COOKIE_NAME`
* `AUTH_COOKIE_TTL_SEC`
    
---
## Test using localhost

```bash
node server.js

# Notes : generate self signed certificate or make changes in index.js for redirect url from https ---> http
```

## ✅ Benefits

* Single minified file **<1 MB**
* Fast execution at CloudFront edge
* Production-ready with **secure cookies** and **JWT validation**
* **JWKS caching** and **state validation** for security
* Easy to maintain, extend, and debug

---

## 🚀 Deployment Flow

1. Write your Lambda@Edge logic in `src/index.js`
2. Zip the output → `okta-auth.zip`
3. Upload to AWS Lambda and attach to CloudFront

## Screenshots

<img width="1253" height="983" alt="okta" src="https://github.com/user-attachments/assets/3ba2ba2d-24a7-4340-8382-3edca5da0410" />


<img width="1778" height="1015" alt="okta-2" src="https://github.com/user-attachments/assets/a595388e-f103-4839-a1f6-59ce9bc1988a" />


