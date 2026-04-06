const STORAGE_KEYS = {
  installTs: "sec_lab3_install_timestamp",
  isActivated: "sec_lab3_activated",
  activationDate: "sec_lab3_activation_date"
};

const TRIAL_DAYS = 30;
const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const VIGENERE_SECRET = "leonid";
const SIGNING_SECRET = "sec_lab3_private_sign_salt";
const PAYLOAD_LENGTH = 25;
const SIGNATURE_LENGTH = 10;
const RAW_KEY_LENGTH = PAYLOAD_LENGTH + SIGNATURE_LENGTH;

const trialInfo = document.getElementById("trialInfo");
const licenseInfo = document.getElementById("licenseInfo");
const licenseInput = document.getElementById("licenseInput");
const activateBtn = document.getElementById("activateBtn");
const resetActivationBtn = document.getElementById("resetActivationBtn");
const textArea = document.getElementById("textArea");
const resultBox = document.getElementById("resultBox");
const hiddenFileInput = document.getElementById("hiddenFileInput");
const actionButtons = document.querySelectorAll("button[data-action]");

initInstallDate();
renderLicenseState();
bindEvents();

function initInstallDate() {
  const stored = localStorage.getItem(STORAGE_KEYS.installTs);
  if (!stored) {
    localStorage.setItem(STORAGE_KEYS.installTs, String(Date.now()));
  }
}

function getTrialDaysPassed() {
  const installTs = Number(localStorage.getItem(STORAGE_KEYS.installTs));
  const msInDay = 1000 * 60 * 60 * 24;
  return Math.floor((Date.now() - installTs) / msInDay);
}

function isActivated() {
  return localStorage.getItem(STORAGE_KEYS.isActivated) === "true";
}

function isBlockedByTrial() {
  return !isActivated() && getTrialDaysPassed() > TRIAL_DAYS;
}

function renderLicenseState() {
  const passedDays = getTrialDaysPassed();
  const leftDays = TRIAL_DAYS - passedDays;

  if (isActivated()) {
    const activationDate = localStorage.getItem(STORAGE_KEYS.activationDate);
    trialInfo.textContent = `Активація виконана. Trial-ліміт не застосовується.`;
    licenseInfo.textContent = `Статус: Licensed. Дата активації: ${activationDate}`;
    setAppEnabled(true);
    return;
  }

  if (isBlockedByTrial()) {
    trialInfo.textContent = `Пробний період завершено (${passedDays} днів з моменту встановлення).`;
    licenseInfo.textContent = "Статус: Заблоковано. Введіть коректний ключ для розблокування.";
    setAppEnabled(false);
    return;
  }

  trialInfo.textContent = `Пробний період активний. Залишилось днів: ${Math.max(leftDays, 0)}.`;
  licenseInfo.textContent = "Статус: Trial mode.";
  setAppEnabled(true);
}

function setAppEnabled(enabled) {
  actionButtons.forEach((btn) => {
    btn.disabled = !enabled;
  });
  textArea.disabled = !enabled;
}

function bindEvents() {
  activateBtn.addEventListener("click", activateLicense);
  resetActivationBtn.addEventListener("click", resetActivation);

  hiddenFileInput.addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) {
      return;
    }
    const content = await file.text();
    textArea.value = content;
    showResult(`Файл "${file.name}" відкрито.`);
    hiddenFileInput.value = "";
  });

  document.querySelectorAll("button[data-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.getAttribute("data-action");
      executeAction(action);
    });
  });
}

function resetActivation() {
  localStorage.removeItem(STORAGE_KEYS.isActivated);
  localStorage.removeItem(STORAGE_KEYS.activationDate);
  licenseInput.value = "";
  renderLicenseState();
  showResult("Активацію скинуто. Повернено Trial-режим.");
}

function activateLicense() {
  const value = licenseInput.value.trim();
  if (!value) {
    showResult("Введіть ключ активації.");
    return;
  }

  if (isValidLicenseKey(value)) {
    localStorage.setItem(STORAGE_KEYS.isActivated, "true");
    localStorage.setItem(STORAGE_KEYS.activationDate, new Date().toLocaleString("uk-UA"));
    showResult("Ключ валідний. Продукт активовано.");
    renderLicenseState();
  } else {
    showResult("Ключ невалідний. Перевірте введення.");
  }
}

function isValidLicenseKey(inputKey) {
  const normalized = inputKey
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");

  if (normalized.length !== RAW_KEY_LENGTH) {
    return false;
  }

  const encryptedPayload = normalized.slice(0, PAYLOAD_LENGTH);
  const signature = normalized.slice(PAYLOAD_LENGTH);
  const expectedSignature = createSignature(encryptedPayload);

  if (signature !== expectedSignature) {
    return false;
  }

  const payload = vigenereDecrypt(encryptedPayload, VIGENERE_SECRET);
  if (payload.length !== PAYLOAD_LENGTH) {
    return false;
  }

  const versionChar = payload[0];
  const issuedAtBase36 = payload.slice(1, 9);
  const nonce = payload.slice(9);

  if (versionChar !== "a") {
    return false;
  }
  if (!/^[a-z0-9]{8}$/.test(issuedAtBase36) || !/^[a-z0-9]{16}$/.test(nonce)) {
    return false;
  }

  return true;
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

function vigenereDecrypt(source, key) {
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
    const decryptedIndex = (srcIndex - keyIndex + ALPHABET.length) % ALPHABET.length;
    result += ALPHABET[decryptedIndex];
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

function executeAction(action) {
  if (isBlockedByTrial()) {
    renderLicenseState();
    showResult("Доступ заблоковано після 30 днів Trial. Потрібна активація.");
    return;
  }

  switch (action) {
    case "new":
      textArea.value = "";
      showResult("Створено новий документ.");
      break;
    case "open":
      hiddenFileInput.click();
      break;
    case "save":
      saveFile();
      break;
    case "print":
      window.print();
      showResult("Відкрито діалог друку.");
      break;
    case "copy":
      navigator.clipboard.writeText(textArea.value);
      showResult("Текст скопійовано в буфер обміну.");
      break;
    case "clear":
      textArea.value = "";
      showResult("Поле очищено.");
      break;
    case "find":
      findOccurrences();
      break;
    case "replace":
      replaceAll();
      break;
    case "upper":
      textArea.value = textArea.value.toUpperCase();
      showResult("Змінено на верхній регістр.");
      break;
    case "lower":
      textArea.value = textArea.value.toLowerCase();
      showResult("Змінено на нижній регістр.");
      break;
    case "reverse":
      textArea.value = textArea.value.split("").reverse().join("");
      showResult("Текст розвернуто.");
      break;
    case "trimSpaces":
      textArea.value = textArea.value.replace(/\s+/g, " ").trim();
      showResult("Зайві пробіли прибрано.");
      break;
    case "stats":
      showStats();
      break;
    case "sortLines":
      sortLines();
      break;
    case "removeEmptyLines":
      removeEmptyLines();
      break;
    default:
      showResult("Невідома команда.");
  }
}

function saveFile() {
  const blob = new Blob([textArea.value], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "document.txt";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showResult("Файл збережено.");
}

function findOccurrences() {
  const query = document.getElementById("findInput").value;
  if (!query) {
    showResult("Введіть фразу для пошуку.");
    return;
  }
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matches = textArea.value.match(new RegExp(escaped, "gi"));
  const count = matches ? matches.length : 0;
  showResult(`Знайдено входжень: ${count}.`);
}

function replaceAll() {
  const from = document.getElementById("replaceFromInput").value;
  const to = document.getElementById("replaceToInput").value;
  if (!from) {
    showResult("Вкажіть текст для заміни.");
    return;
  }
  const escaped = from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(escaped, "g");
  const before = textArea.value;
  textArea.value = textArea.value.replace(regex, to);
  const replaced = (before.match(regex) || []).length;
  showResult(`Виконано замін: ${replaced}.`);
}

function showStats() {
  const text = textArea.value;
  const chars = text.length;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const lines = text ? text.split(/\r?\n/).length : 0;
  showResult(`Символи: ${chars}, слова: ${words}, рядки: ${lines}.`);
}

function sortLines() {
  const sorted = textArea.value
    .split(/\r?\n/)
    .sort((a, b) => a.localeCompare(b, "uk"))
    .join("\n");
  textArea.value = sorted;
  showResult("Рядки відсортовано.");
}

function removeEmptyLines() {
  textArea.value = textArea.value
    .split(/\r?\n/)
    .filter((line) => line.trim() !== "")
    .join("\n");
  showResult("Порожні рядки видалено.");
}

function showResult(message) {
  resultBox.textContent = message;
}
