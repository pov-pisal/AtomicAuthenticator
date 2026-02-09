const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function normalizeSecret(secret) {
  return secret.replace(/\s+/g, "").toUpperCase();
}

export function base32ToBytes(input) {
  const clean = normalizeSecret(input).replace(/=+$/, "");
  let bits = "";
  for (const char of clean) {
    const index = base32Alphabet.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid Base32 secret");
    }
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

export async function generateTOTP(secret, now = Date.now()) {
  const keyData = base32ToBytes(secret);
  const counter = Math.floor(now / 1000 / 30);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(4, counter);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const hmac = await crypto.subtle.sign("HMAC", key, buffer);
  const hmacView = new DataView(hmac);
  const offset = hmacView.getUint8(hmac.byteLength - 1) & 0x0f;
  const binCode =
    ((hmacView.getUint8(offset) & 0x7f) << 24) |
    ((hmacView.getUint8(offset + 1) & 0xff) << 16) |
    ((hmacView.getUint8(offset + 2) & 0xff) << 8) |
    (hmacView.getUint8(offset + 3) & 0xff);

  const otp = (binCode % 1000000).toString().padStart(6, "0");
  return otp;
}

export function parseOtpauth(url) {
  if (!url.startsWith("otpauth://totp/")) {
    return null;
  }

  try {
    const parsed = new URL(url);
    const labelRaw = decodeURIComponent(parsed.pathname.replace("/", ""));
    const params = parsed.searchParams;
    const secret = params.get("secret") || "";
    const issuerParam = params.get("issuer") || "";

    let issuer = issuerParam;
    let label = labelRaw;
    if (labelRaw.includes(":")) {
      const [labelIssuer, labelName] = labelRaw.split(":");
      issuer = issuer || labelIssuer;
      label = labelName;
    }

    return {
      issuer: issuer.trim(),
      label: label.trim(),
      secret: secret.trim(),
    };
  } catch (error) {
    return null;
  }
}
