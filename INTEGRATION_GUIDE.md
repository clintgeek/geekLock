# Integrating geekLock

geekLock is designed to be completely language-agnostic. Because it is an independent HTTP sidecar, any application that can make a web request can use it to secure its data.

Below are practical examples of how to hook geekLock into your existing services.

---

## Example 1: Node.js (Express & Mongoose)
*The most common use case for the GeekSuite ecosystem.*

Instead of storing raw text in MongoDB, you can use a Mongoose **Pre-Save Hook** to automatically encrypt data before it hits the database, and a method to decrypt it when reading.

### Setup
Install `axios` in your Node project:
```bash
npm install axios
```

### Implementation (`User.model.js`)

```javascript
const mongoose = require('mongoose');
const axios = require('axios');

// Configuration: Point to the geekLock sidecar
const GEEKLOCK_URL = process.env.GEEKLOCK_URL || 'http://127.0.0.1:9090';

const userSchema = new mongoose.Schema({
  email: { type: String, required: true },
  
  // Notice we store the 'envelope' (encrypted blob), not the raw 'ssn'
  ssnEnvelope: { type: String, required: true } 
});

// 🔒 Encrypt BEFORE Saving to MongoDB
userSchema.statics.createSecureUser = async function(email, plainTextSSN) {
  try {
    // 1. Send plaintext to the sidecar
    const response = await axios.post(`${GEEKLOCK_URL}/encrypt`, {
      data: plainTextSSN
    });
    
    // 2. The sidecar returns a secure Base64 envelope
    const envelope = response.data.envelope;
    
    // 3. Save the envelope to the database
    return await this.create({
      email: email,
      ssnEnvelope: envelope
    });
  } catch (error) {
    console.error("Encryption failed:", error.message);
    throw new Error("Security boundary failed during user creation.");
  }
};

// 🔓 Decrypt AFTER Fetching from MongoDB
userSchema.methods.getDecryptedSSN = async function() {
  try {
    // 1. Send the envelope to the sidecar
    const response = await axios.post(`${GEEKLOCK_URL}/decrypt`, {
      envelope: this.ssnEnvelope
    });
    
    // 2. Return the original plaintext
    return response.data.data;
  } catch (error) {
    console.error("Decryption failed:", error.message);
    throw new Error("Failed to decrypt secure data.");
  }
};

module.exports = mongoose.model('User', userSchema);
```

### Usage
```javascript
const User = require('./User.model');

// Create user (SSN is encrypted in transit and saved as an envelope)
const newUser = await User.createSecureUser("jane@example.com", "123-45-6789");

// Read user (Envelope is fetched, decrypted via sidecar, and returned)
const plainSSN = await newUser.getDecryptedSSN(); 
console.log(plainSSN); // "123-45-6789"
```

---

## Example 2: Python (FastAPI / Requests)

If you are using Python, integrating geekLock is just as simple using the `requests` library.

### Implementation

```python
import requests

GEEKLOCK_URL = "http://127.0.0.1:9090"

def secure_data(sensitive_text: str) -> str:
    """Sends plaintext to geekLock and returns the secure envelope."""
    response = requests.post(f"{GEEKLOCK_URL}/encrypt", json={"data": sensitive_text})
    
    if response.status_code == 200:
        return response.json()["envelope"]
    else:
        raise Exception(f"Encryption failed: {response.text}")

def read_data(envelope: str) -> str:
    """Sends an envelope to geekLock and returns the plaintext."""
    response = requests.post(f"{GEEKLOCK_URL}/decrypt", json={"envelope": envelope})
    
    if response.status_code == 200:
        return response.json()["data"]
    else:
        raise Exception(f"Decryption failed: {response.text}")

# --- Example Usage --- #

# 1. Encrypt and store to your database
my_secure_envelope = secure_data("My secret database connection string")
print(f"Stored in DB: {my_secure_envelope}\n")

# 2. Fetch from database and decrypt
original_text = read_data(my_secure_envelope)
print(f"Decrypted: {original_text}")
```

---

## Architecture Tips for Integration

1.  **Keep it Local:** geekLock should run on the *same private network* (or same machine/pod) as your backend API. Never expose geekLock directly to the public internet.
2.  **Stateless Design:** geekLock holds no state. If your web-tier scales up, you can safely scale geekLock up behind a load balancer without any issues.
3.  **Fail Securely:** If geekLock is unreachable, your application should fail to save/read data rather than bypass the encryption flow. 
