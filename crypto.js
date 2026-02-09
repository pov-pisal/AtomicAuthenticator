const encoder = new TextEncoder();

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export async function deriveKey(pin, salt, iterations = 150000) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(pin),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptVault(pin, data) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 150000;
  const key = await deriveKey(pin, salt, iterations);
  const plaintext = encoder.encode(JSON.stringify(data));

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  return {
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv.buffer),
    salt: toBase64(salt.buffer),
    iterations,
    version: 1,
  };
}

export async function decryptVault(pin, record) {
  if (!record?.ciphertext || !record?.iv || !record?.salt) {
    throw new Error("Invalid vault record");
  }
  const iterations = record.iterations || 150000;
  const salt = new Uint8Array(fromBase64(record.salt));
  const iv = new Uint8Array(fromBase64(record.iv));
  const key = await deriveKey(pin, salt, iterations);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      fromBase64(record.ciphertext)
    );
  } catch (error) {
    throw new Error("Invalid PIN");
  }

  const decoded = new TextDecoder().decode(plaintext);
  return JSON.parse(decoded);
}
