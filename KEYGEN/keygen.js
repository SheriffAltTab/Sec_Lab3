const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const VIGENERE_SECRET = "leonid";
const SIGNING_SECRET = "sec_lab3_private_sign_salt";
const PAYLOAD_LENGTH = 25;
const SIGNATURE_LENGTH = 10;

const generateBtn = document.getElementById("generateBtn");
const copyBtn = document.getElementById("copyBtn");
const keyOutput = document.getElementById("keyOutput");
const info = document.getElementById("info");

generateBtn.addEventListener("click", () => {
  const key = generateComplexLicenseKey();
  keyOutput.value = key;
  info.textContent = "Ключ згенеровано. Його можна вводити у веб-застосунок.";
});

copyBtn.addEventListener("click", async () => {
  if (!keyOutput.value) {
    info.textContent = "Спочатку згенеруйте ключ.";
    return;
  }
  await navigator.clipboard.writeText(keyOutput.value);
  info.textContent = "Ключ скопійовано.";
});

function generateComplexLicenseKey() {
  const version = "a";
  const issuedAtBase36 = Date.now().toString(36).slice(-8).padStart(8, "0");
  const nonce = randomFromAlphabet(16);
  const payload = `${version}${issuedAtBase36}${nonce}`;
  if (payload.length !== PAYLOAD_LENGTH) {
    throw new Error("Invalid payload size.");
  }

  const encryptedPayload = vigenereEncrypt(payload, VIGENERE_SECRET);
  const signature = createSignature(encryptedPayload);
  const rawKey = `${encryptedPayload}${signature}`;
  return splitByFive(rawKey).toUpperCase();
}

function randomFromAlphabet(length) {
  let result = "";
  for (let i = 0; i < length; i += 1) {
    const idx = Math.floor(Math.random() * ALPHABET.length);
    result += ALPHABET[idx];
  }
  return result;
}

function splitByFive(value) {
  const chunks = [];
  for (let i = 0; i < value.length; i += 5) {
    chunks.push(value.slice(i, i + 5));
  }
  return chunks.join("-");
}

function vigenereEncrypt(source, key) {
  const cleanKey = key.toLowerCase();
  let result = "";
  let keyPos = 0;

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i].toLowerCase();
    const srcIndex = ALPHABET.indexOf(ch);
    if (srcIndex === -1) {
      result += ch;
      continue;
    }

    const keyChar = cleanKey[keyPos % cleanKey.length];
    const keyIndex = ALPHABET.indexOf(keyChar);
    const encryptedIndex = (srcIndex + keyIndex) % ALPHABET.length;
    result += ALPHABET[encryptedIndex];
    keyPos += 1;
  }

  return result;
}

function createSignature(encryptedPayload) {
  const source = `${encryptedPayload}|${SIGNING_SECRET}`;
  let hash = 0x811c9dc5;

  for (let i = 0; i < source.length; i += 1) {
    hash ^= source.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }

  let signature = "";
  let value = hash;
  for (let i = 0; i < SIGNATURE_LENGTH; i += 1) {
    signature += ALPHABET[value % ALPHABET.length];
    value = Math.floor(value / ALPHABET.length) ^ (value >>> 3);
  }

  return signature;
}
