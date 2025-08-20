# SecretKeeper API Reference

## Overview

This document provides detailed technical specifications for the SecretKeeper API. SecretKeeper follows RESTful principles with JSON-based request and response bodies.

## Base URL

```text
https://your-secretkeeper-domain.com/api
```

Replace `your-secretkeeper-domain.com` with your actual deployment domain.

## Authentication

SecretKeeper API endpoints do not require authentication. Security is based on the secrecy of generated URLs and the one-time access pattern.

## Rate Limiting

All API endpoints are rate-limited to prevent abuse. When rate limits are exceeded, the API returns a `429 Too Many Requests` status code with a `Retry-After` header indicating when the client can retry.

## Endpoints

### Create Secret

Creates a new encrypted secret with a specified time-to-live.

**Endpoint:** `POST /create`

**Rate Limit:** 10 requests per minute per IP

**Request Body:**

```json
{
  "ciphertext": "string",  // Required. Base64-encoded encrypted data
  "ttl": 24.0              // Optional. Time-to-live in hours (0.1 to 168)
}
```

**Response:**

```json
{
  "success": true,
  "secret_id": "string",    // The unique identifier for accessing the secret
  "expires_in_hours": 24.0  // The actual TTL that was applied
}
```

**Status Codes:**

- `201 Created`: Secret successfully created
- `400 Bad Request`: Invalid input parameters
- `413 Payload Too Large`: Ciphertext exceeds size limits
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

**Example Request:**

```bash
curl -X POST https://your-secretkeeper-domain.com/api/create \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "AE3DKfj9s2lm...[truncated]",
    "ttl": 1.0
  }'
```

**Example Response:**

```json
{
  "success": true,
  "secret_id": "XVlBzgbaiC-MYozG-TdxIeQ",
  "expires_in_hours": 1.0
}
```

### Retrieve Secret

Retrieves and invalidates a secret. This is a one-time operation - once accessed, the secret is permanently deleted.

**Endpoint:** `GET /secret/{secret_id}`

**Rate Limit:** 20 requests per minute per IP

**Path Parameters:**

- `secret_id`: The unique identifier for the secret

**Response:**

```json
{
  "success": true,
  "ciphertext": "string"  // Base64-encoded encrypted data
}
```

**Status Codes:**

- `200 OK`: Secret successfully retrieved
- `400 Bad Request`: Invalid secret ID format
- `404 Not Found`: Secret not found, expired, or already accessed
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

**Example Request:**

```bash
curl -X GET https://your-secretkeeper-domain.com/api/secret/XVlBzgbaiC-MYozG-TdxIeQ
```

**Example Response:**

```json
{
  "success": true,
  "ciphertext": "AE3DKfj9s2lm...[truncated]"
}
```

### Generate QR Code

Generates a QR code image for the given secret URL.

**Endpoint:** `GET /qr/{secret_id}`

**Rate Limit:** 5 requests per minute per IP

**Path Parameters:**

- `secret_id`: The unique identifier for the secret

**Response:**

- Content-Type: `image/png`
- Body: Binary PNG image data

**Status Codes:**

- `200 OK`: QR code successfully generated
- `400 Bad Request`: Invalid secret ID format
- `404 Not Found`: Secret not found or expired
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

**Example Request:**

```bash
curl -X GET https://your-secretkeeper-domain.com/api/qr/XVlBzgbaiC-MYozG-TdxIeQ --output qr-code.png
```

### Health Check

Returns the current health status of the service.

**Endpoint:** `GET /health`

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2025-08-20T12:00:00Z"
}
```

**Status Codes:**

- `200 OK`: Service is healthy
- `500 Internal Server Error`: Service is unhealthy

**Example Request:**

```bash
curl -X GET https://your-secretkeeper-domain.com/api/health
```

**Example Response:**

```json
{
  "status": "healthy",
  "timestamp": "2025-08-20T12:34:56Z"
}
```

## Error Responses

All API errors follow a consistent format:

```json
{
  "error": "Error Type",
  "message": "Human-readable error message",
  "retry_after": 60  // Only included for rate limit errors
}
```

Common error types:

| Error Type | Status Code | Description |
|------------|-------------|-------------|
| Bad Request | 400 | Invalid input parameters |
| Not Found | 404 | Resource not found |
| Payload Too Large | 413 | Request body exceeds size limits |
| Rate Limit Exceeded | 429 | Too many requests in a given time |
| Internal Server Error | 500 | Unexpected server error |

## Client Implementation Guide

### Encryption/Decryption

SecretKeeper uses client-side encryption with the Web Cryptography API. Here's a simplified example in JavaScript:

```javascript
// Generate a random encryption key
async function generateKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// Export key to base64 format for URL fragment
async function exportKey(key) {
  const exported = await crypto.subtle.exportKey('raw', key);
  return btoa(String.fromCharCode.apply(null, new Uint8Array(exported)));
}

// Import key from base64 format
async function importKey(base64Key) {
  const binaryKey = atob(base64Key);
  const keyData = new Uint8Array(binaryKey.length);
  for (let i = 0; i < binaryKey.length; i++) {
    keyData[i] = binaryKey.charCodeAt(i);
  }
  
  return await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
}

// Encrypt plaintext
async function encrypt(plaintext, key) {
  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Convert plaintext to bytes
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  // Encrypt the data
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, tagLength: 128 },
    key,
    data
  );
  
  // Combine IV and encrypted data
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  
  // Return base64 encoded result
  return btoa(String.fromCharCode.apply(null, combined));
}

// Decrypt ciphertext
async function decrypt(base64Ciphertext, key) {
  // Decode the base64 data
  const binaryCiphertext = atob(base64Ciphertext);
  const combined = new Uint8Array(binaryCiphertext.length);
  for (let i = 0; i < binaryCiphertext.length; i++) {
    combined[i] = binaryCiphertext.charCodeAt(i);
  }
  
  // Extract IV (first 12 bytes) and ciphertext
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  
  // Decrypt the data
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv, tagLength: 128 },
    key,
    ciphertext
  );
  
  // Convert bytes back to text
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}
```

### Creating a Secret

```javascript
async function createSecret(plaintext, ttlHours) {
  try {
    // Generate encryption key
    const key = await generateKey();
    
    // Encrypt the plaintext
    const ciphertext = await encrypt(plaintext, key);
    
    // Export key for URL fragment
    const exportedKey = await exportKey(key);
    
    // Send encrypted data to server
    const response = await fetch('/api/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ciphertext: ciphertext,
        ttl: ttlHours
      })
    });
    
    const result = await response.json();
    
    if (!result.success) {
      throw new Error(result.message || 'Failed to create secret');
    }
    
    // Construct the secure URL with key in fragment
    const url = `${window.location.origin}/view?id=${result.secret_id}#${exportedKey}`;
    
    return url;
  } catch (error) {
    console.error('Error creating secret:', error);
    throw error;
  }
}
```

### Viewing a Secret

```javascript
async function viewSecret(secretId, encryptionKey) {
  try {
    // Fetch encrypted data from server
    const response = await fetch(`/api/secret/${secretId}`);
    
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Secret not found, already accessed, or expired');
      }
      throw new Error(`HTTP Error: ${response.status}`);
    }
    
    const result = await response.json();
    
    if (!result.success) {
      throw new Error(result.message || 'Failed to retrieve secret');
    }
    
    // Import the encryption key
    const key = await importKey(encryptionKey);
    
    // Decrypt the data
    const plaintext = await decrypt(result.ciphertext, key);
    
    return plaintext;
  } catch (error) {
    console.error('Error viewing secret:', error);
    throw error;
  }
}
```

## Security Considerations

When implementing clients that interact with the SecretKeeper API, consider the following security best practices:

1. **Always use HTTPS** for all API requests
2. **Implement client-side encryption** properly:
   - Use secure random generators for keys and IVs
   - Use standard algorithms (AES-GCM with 256-bit keys)
   - Clear sensitive data from memory when possible
3. **Handle URL fragments securely**:
   - Ensure the fragment is not sent to the server
   - Clear browser history after generating/viewing secrets
4. **Validate server responses**:
   - Verify success flag in responses
   - Handle errors appropriately
5. **Respect rate limits**:
   - Implement exponential backoff for retries
   - Display appropriate messages to users

## API Changes and Versioning

The current API is version 1.0. Future changes will follow these principles:

- Breaking changes will result in a new API version
- New endpoints or optional parameters may be added without version changes
- Deprecated endpoints will be supported for at least 6 months

API versions are reflected in the documentation only. The current endpoints do not include version numbers in the URL.

## Support

For API support, contact:

- Email: [api-support@yourcompany.com](mailto:api-support@yourcompany.com)
- Documentation: [https://docs.yourcompany.com/secretkeeper/api](https://docs.yourcompany.com/secretkeeper/api)
- Status page: [https://status.yourcompany.com](https://status.yourcompany.com)
