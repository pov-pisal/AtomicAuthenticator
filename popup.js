import { encryptVault, decryptVault } from "./crypto.js";
import {
  generateTOTP,
  parseOtpauth,
  normalizeSecret,
  base32ToBytes,
} from "./totp.js";
import {
  getVaultRecord,
  setVaultRecord,
  getMeta,
  updateMeta,
  getSession,
  setSession,
  clearSession as clearStoredSession,
} from "./storage.js";

const defaultInactivityMs = 2 * 60 * 1000;

const elements = {
  lockedView: document.getElementById("lockedView"),
  lockTitle: document.getElementById("lockTitle"),
  lockSubtitle: document.getElementById("lockSubtitle"),
  createPinFields: document.getElementById("createPinFields"),
  unlockPinField: document.getElementById("unlockPinField"),
  newPin: document.getElementById("newPin"),
  confirmPin: document.getElementById("confirmPin"),
  unlockPin: document.getElementById("unlockPin"),
  unlockBtn: document.getElementById("unlockBtn"),
  lockError: document.getElementById("lockError"),
  editAccountsBtn: document.getElementById("editAccountsBtn"),
  settingsBtn: document.getElementById("settingsBtn"),
  mainView: document.getElementById("mainView"),
  searchInput: document.getElementById("searchInput"),
  addAccountBtn: document.getElementById("addAccountBtn"),
  lockTimeoutSelect: document.getElementById("lockTimeoutSelect"),
  emptyState: document.getElementById("emptyState"),
  accountsList: document.getElementById("accountsList"),
  toast: document.getElementById("toast"),
  modal: document.getElementById("modal"),
  modalTitle: document.getElementById("modalTitle"),
  closeModalBtn: document.getElementById("closeModalBtn"),
  secretInput: document.getElementById("secretInput"),
  issuerInput: document.getElementById("issuerInput"),
  labelInput: document.getElementById("labelInput"),
  saveAccountBtn: document.getElementById("saveAccountBtn"),
  cancelAccountBtn: document.getElementById("cancelAccountBtn"),
  modalError: document.getElementById("modalError"),
  deleteModal: document.getElementById("deleteModal"),
  closeDeleteBtn: document.getElementById("closeDeleteBtn"),
  confirmDeleteBtn: document.getElementById("confirmDeleteBtn"),
  cancelDeleteBtn: document.getElementById("cancelDeleteBtn"),
  editAccountsModal: document.getElementById("editAccountsModal"),
  closeEditAccountsBtn: document.getElementById("closeEditAccountsBtn"),
  editAccountsList: document.getElementById("editAccountsList"),
  settingsModal: document.getElementById("settingsModal"),
  closeSettingsBtn: document.getElementById("closeSettingsBtn"),
  settingsBackBtn: document.getElementById("settingsBackBtn"),
  settingsList: document.getElementById("settingsList"),
  currentPinInput: document.getElementById("currentPinInput"),
  newPinInput: document.getElementById("newPinInput"),
  confirmNewPinInput: document.getElementById("confirmNewPinInput"),
  changePinBtn: document.getElementById("changePinBtn"),
  changePinError: document.getElementById("changePinError"),
  backupBtn: document.getElementById("backupBtn"),
  copyBackupBtn: document.getElementById("copyBackupBtn"),
  exportText: document.getElementById("exportText"),
  importText: document.getElementById("importText"),
  importBtn: document.getElementById("importBtn"),
  importFileBtn: document.getElementById("importFileBtn"),
  importFile: document.getElementById("importFile"),
  importError: document.getElementById("importError"),
  backupStatus: document.getElementById("backupStatus"),
  backupDate: document.getElementById("backupDate"),
  settingsChangePin: document.getElementById("settingsChangePin"),
  settingsBackup: document.getElementById("settingsBackup"),
  settingsPreferences: document.getElementById("settingsPreferences"),
  themeSelect: document.getElementById("themeSelect"),
  sortSelect: document.getElementById("sortSelect"),
  prefSaveBtn: document.getElementById("prefSaveBtn"),
  prefCancelBtn: document.getElementById("prefCancelBtn"),
};

let vaultRecord = null;
let vault = null;
let meta = null;
let sessionPin = null;
let sessionData = null;
let currentCounter = null;
let lastActivityUpdate = 0;
let editingId = null;
let pendingDeleteId = null;
let preferencesDraft = null;
let dragSrcId = null;          // id of account being dragged
const codes = new Map();

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("show");
  setTimeout(() => elements.toast.classList.remove("show"), 1600);
}

function showLockedView({ createMode }) {
  elements.lockedView.classList.remove("hidden");
  elements.lockedView.setAttribute("aria-hidden", "false");
  elements.lockedView.removeAttribute("inert");
  elements.mainView.classList.add("hidden");
  elements.mainView.setAttribute("aria-hidden", "true");
  elements.mainView.setAttribute("inert", "");
  elements.lockError.textContent = "";

  if (createMode) {
    elements.lockTitle.textContent = "Create PIN";
    elements.lockSubtitle.textContent = "Set a PIN to encrypt your vault.";
    elements.createPinFields.classList.remove("hidden");
    elements.unlockPinField.classList.add("hidden");
    elements.unlockBtn.textContent = "Create";
  } else {
    elements.lockTitle.textContent = "Unlock vault";
    elements.lockSubtitle.textContent = "Enter your PIN to unlock.";
    elements.createPinFields.classList.add("hidden");
    elements.unlockPinField.classList.remove("hidden");
    elements.unlockBtn.textContent = "Unlock";
  }

  const focusTarget = createMode ? elements.newPin : elements.unlockPin;
  focusTarget?.focus();
}

function showMainView() {
  elements.lockedView.classList.add("hidden");
  elements.lockedView.setAttribute("aria-hidden", "true");
  elements.lockedView.setAttribute("inert", "");
  elements.mainView.classList.remove("hidden");
  elements.mainView.setAttribute("aria-hidden", "false");
  elements.mainView.removeAttribute("inert");
  renderAccounts();
  elements.searchInput?.focus();
}

function getLockTimeoutMs() {
  if (!meta) return defaultInactivityMs;
  if (typeof meta.lockTimeoutMs !== "number") return defaultInactivityMs;
  return meta.lockTimeoutMs;
}

function getTheme() {
  return meta?.theme || "dark";
}

function getSortMode() {
  return meta?.sortMode || "newest";
}

function applyTheme(theme) {
  const resolved = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = resolved;
}

function normalizeSortText(value) {
  return (value || "").toString().trim().toLowerCase();
}

function sortAccounts(list) {
  const mode = getSortMode();
  const sorted = [...list];
  // "manual" preserves the order stored in vault.accounts
  if (mode === "manual") return sorted;
  if (mode === "oldest") {
    sorted.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    return sorted;
  }
  if (mode === "newest") {
    sorted.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    return sorted;
  }
  if (mode === "issuer-asc" || mode === "issuer-desc") {
    sorted.sort((a, b) =>
      normalizeSortText(a.issuer).localeCompare(
        normalizeSortText(b.issuer),
        undefined,
        { sensitivity: "base" },
      ),
    );
    if (mode === "issuer-desc") sorted.reverse();
    return sorted;
  }
  if (mode === "label-asc" || mode === "label-desc") {
    sorted.sort((a, b) =>
      normalizeSortText(a.label).localeCompare(
        normalizeSortText(b.label),
        undefined,
        { sensitivity: "base" },
      ),
    );
    if (mode === "label-desc") sorted.reverse();
    return sorted;
  }
  return sorted;
}

function clearSession() {
  vault = null;
  sessionPin = null;
  currentCounter = null;
  codes.clear();
}

function isPinValid(pin) {
  return /^\d{6,}$/.test(pin);
}

async function saveVault() {
  if (!vault || !sessionPin) return;
  vaultRecord = await encryptVault(sessionPin, vault);
  await setVaultRecord(vaultRecord);
}

async function setLocked(locked) {
  if (locked) {
    clearSession();
    await clearStoredSession();
  }
  meta = await updateMeta({ locked, lastActive: locked ? 0 : Date.now() });
}

async function handleUnlock() {
  const createMode = !vaultRecord;
  elements.lockError.textContent = "";

  if (createMode) {
    const pin = elements.newPin.value.trim();
    const confirm = elements.confirmPin.value.trim();
    if (!isPinValid(pin)) {
      elements.lockError.textContent = "PIN must be at least 6 digits.";
      return;
    }
    if (pin !== confirm) {
      elements.lockError.textContent = "PINs do not match.";
      return;
    }

    vault = { accounts: [], createdAt: Date.now() };
    sessionPin = pin;
    vaultRecord = await encryptVault(pin, vault);
    await setVaultRecord(vaultRecord);
    await setLocked(false);
    showMainView();
    return;
  }

  const pin = elements.unlockPin.value.trim();
  if (!isPinValid(pin)) {
    elements.lockError.textContent = "Invalid PIN.";
    return;
  }

  try {
    vault = await decryptVault(pin, vaultRecord);
    sessionPin = pin;
    sessionData = { pin, lastActive: Date.now() };
    await setSession(sessionData);
    await setLocked(false);
    showMainView();
  } catch (error) {
    elements.lockError.textContent = "Incorrect PIN.";
  }
}

function openModal(editAccount = null) {
  editingId = editAccount?.id || null;
  elements.modalTitle.textContent = editingId ? "Edit account" : "Add account";
  elements.secretInput.value = editAccount?.secret || "";
  elements.issuerInput.value = editAccount?.issuer || "";
  elements.labelInput.value = editAccount?.label || "";
  elements.modalError.textContent = "";
  elements.modal.classList.remove("hidden");
  elements.modal.setAttribute("aria-hidden", "false");
  elements.modal.removeAttribute("inert");
  elements.secretInput?.focus();
}

function closeModal() {
  elements.modal.classList.add("hidden");
  elements.modal.setAttribute("aria-hidden", "true");
  elements.modal.setAttribute("inert", "");
  elements.secretInput.value = "";
  elements.issuerInput.value = "";
  elements.labelInput.value = "";
  elements.modalError.textContent = "";
  editingId = null;
  elements.addAccountBtn?.focus();
}

function openDeleteModal(accountId) {
  pendingDeleteId = accountId;
  elements.deleteModal.classList.remove("hidden");
  elements.deleteModal.setAttribute("aria-hidden", "false");
  elements.deleteModal.removeAttribute("inert");
  elements.confirmDeleteBtn?.focus();
}

function closeDeleteModal() {
  elements.deleteModal.classList.add("hidden");
  elements.deleteModal.setAttribute("aria-hidden", "true");
  elements.deleteModal.setAttribute("inert", "");
  pendingDeleteId = null;
}

function openEditAccountsModal() {
  if (!vault) return;
  elements.editAccountsModal.classList.remove("hidden");
  elements.editAccountsModal.setAttribute("aria-hidden", "false");
  elements.editAccountsModal.removeAttribute("inert");
  renderEditAccountsList();
}

function closeEditAccountsModal() {
  elements.editAccountsModal.classList.add("hidden");
  elements.editAccountsModal.setAttribute("aria-hidden", "true");
  elements.editAccountsModal.setAttribute("inert", "");
}

function renderEditAccountsList() {
  if (!vault || !elements.editAccountsList) return;
  elements.editAccountsList.innerHTML = "";
  if (vault.accounts.length === 0) {
    elements.editAccountsList.innerHTML =
      '<div class="muted">No accounts to edit.</div>';
    return;
  }
  sortAccounts(vault.accounts).forEach((account) => {
    const row = document.createElement("div");
    row.className = "edit-item";
    row.setAttribute("role", "listitem");

    const meta = document.createElement("div");
    meta.className = "edit-meta";
    const issuer = document.createElement("strong");
    issuer.textContent = account.issuer || "Account";
    const label = document.createElement("span");
    label.textContent = account.label || "(no label)";
    meta.append(issuer, label);

    const actions = document.createElement("div");
    actions.className = "edit-actions";
    const editBtn = document.createElement("button");
    editBtn.className = "ghost";
    editBtn.type = "button";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => {
      closeEditAccountsModal();
      openModal(account);
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "ghost";
    deleteBtn.type = "button";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => {
      openDeleteModal(account.id);
    });

    actions.append(editBtn, deleteBtn);
    row.append(meta, actions);
    elements.editAccountsList.appendChild(row);
  });
}

function openSettingsModal() {
  if (meta?.locked) {
    showToast("Unlock vault first");
    return;
  }
  elements.settingsModal.classList.remove("hidden");
  elements.settingsModal.setAttribute("aria-hidden", "false");
  elements.settingsModal.removeAttribute("inert");
  elements.changePinError.textContent = "";
  elements.currentPinInput.value = "";
  elements.newPinInput.value = "";
  elements.confirmNewPinInput.value = "";
  elements.lockTimeoutSelect.value = String(getLockTimeoutMs());
  if (elements.themeSelect) {
    elements.themeSelect.value = getTheme();
  }
  if (elements.sortSelect) {
    elements.sortSelect.value = getSortMode();
  }
  preferencesDraft = {
    lockTimeoutMs: getLockTimeoutMs(),
    sortMode: getSortMode(),
    theme: getTheme(),
  };
  showSettingsList();
  elements.currentPinInput?.focus();
}

function closeSettingsModal() {
  elements.settingsModal.classList.add("hidden");
  elements.settingsModal.setAttribute("aria-hidden", "true");
  elements.settingsModal.setAttribute("inert", "");
  showSettingsList();
}

function hideAllSettingsSections() {
  [
    elements.settingsChangePin,
    elements.settingsBackup,
    elements.settingsPreferences,
  ].forEach((section) => {
    if (!section) return;
    section.classList.add("hidden");
    section.setAttribute("aria-hidden", "true");
  });
}

function showSettingsList() {
  hideAllSettingsSections();
  elements.settingsList?.classList.remove("hidden");
  elements.settingsList?.setAttribute("aria-hidden", "false");
  elements.settingsBackBtn?.classList.add("hidden");
  elements.settingsBackBtn?.setAttribute("aria-hidden", "true");
}

function hideSettingsList() {
  elements.settingsList?.classList.add("hidden");
  elements.settingsList?.setAttribute("aria-hidden", "true");
  elements.settingsBackBtn?.classList.remove("hidden");
  elements.settingsBackBtn?.setAttribute("aria-hidden", "false");
}

function openSettingsSection(key) {
  hideAllSettingsSections();
  const map = {
    "change-pin": elements.settingsChangePin,
    backup: elements.settingsBackup,
    preferences: elements.settingsPreferences,
  };
  const section = map[key];
  if (!section) return;
  hideSettingsList();
  section.classList.remove("hidden");
  section.setAttribute("aria-hidden", "false");
  if (key === "change-pin") {
    elements.currentPinInput?.focus();
  }
  if (key === "preferences") {
    preferencesDraft = {
      lockTimeoutMs: getLockTimeoutMs(),
      sortMode: getSortMode(),
      theme: getTheme(),
    };
    elements.lockTimeoutSelect.value = String(preferencesDraft.lockTimeoutMs);
    if (elements.themeSelect) {
      elements.themeSelect.value = preferencesDraft.theme;
    }
    if (elements.sortSelect) {
      elements.sortSelect.value = preferencesDraft.sortMode;
    }
  }
  if (key === "backup") {
    populateExportBackup();
  }
}

async function savePreferences() {
  if (!preferencesDraft) return;
  meta = await updateMeta({
    lockTimeoutMs: preferencesDraft.lockTimeoutMs,
    sortMode: preferencesDraft.sortMode,
    theme: preferencesDraft.theme,
  });
  if (sessionData) {
    sessionData.lastActive = Date.now();
    await setSession(sessionData);
  }
  applyTheme(preferencesDraft.theme);
  renderAccounts();
  showToast("Preferences saved");
  closeSettingsModal();
}

function cancelPreferences() {
  preferencesDraft = {
    lockTimeoutMs: getLockTimeoutMs(),
    sortMode: getSortMode(),
    theme: getTheme(),
  };
  elements.lockTimeoutSelect.value = String(preferencesDraft.lockTimeoutMs);
  if (elements.themeSelect) {
    elements.themeSelect.value = preferencesDraft.theme;
  }
  if (elements.sortSelect) {
    elements.sortSelect.value = preferencesDraft.sortMode;
  }
}

async function confirmDelete() {
  if (!vault || !pendingDeleteId) {
    closeDeleteModal();
    return;
  }
  vault.accounts = vault.accounts.filter((acc) => acc.id !== pendingDeleteId);
  await saveVault();
  closeDeleteModal();
  renderAccounts();
  if (!elements.editAccountsModal.classList.contains("hidden")) {
    renderEditAccountsList();
  }
}

async function handleChangePin() {
  elements.changePinError.textContent = "";
  const currentPin = elements.currentPinInput.value.trim();
  const newPin = elements.newPinInput.value.trim();
  const confirmPin = elements.confirmNewPinInput.value.trim();

  if (!isPinValid(currentPin) || !isPinValid(newPin)) {
    elements.changePinError.textContent = "PIN must be at least 6 digits.";
    return;
  }
  if (newPin !== confirmPin) {
    elements.changePinError.textContent = "New PINs do not match.";
    return;
  }

  try {
    const decrypted = await decryptVault(currentPin, vaultRecord);
    vault = decrypted;
    vaultRecord = await encryptVault(newPin, vault);
    sessionPin = newPin;
    sessionData = { pin: newPin, lastActive: Date.now() };
    await setVaultRecord(vaultRecord);
    await setSession(sessionData);
    elements.currentPinInput.value = "";
    elements.newPinInput.value = "";
    elements.confirmNewPinInput.value = "";
    showToast("PIN updated");
  } catch (error) {
    elements.changePinError.textContent = "Current PIN is incorrect.";
  }
}

async function handleBackup() {
  if (!vaultRecord) {
    showToast("No vault to backup");
    return;
  }
  const payload = buildBackupPayload();
  if (!payload) {
    showToast("No vault data to backup — make sure you are unlocked");
    return;
  }

  const timestamp = new Date().toISOString().split("T")[0];
  const filename = `atomic-authenticator-backup-${timestamp}.json`;

  // ── Method 1: File System Access API (save dialog) ──────────────────────
  // Works in Chrome extension popup pages (secure context, user gesture present).
  if (typeof window.showSaveFilePicker === "function") {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: filename,
        types: [{ description: "JSON backup", accept: { "application/json": [".json"] } }],
      });
      const writable = await handle.createWritable();
      await writable.write(payload);
      await writable.close();
      showToast("✓ Backup saved successfully");
      return;
    } catch (err) {
      if (err.name === "AbortError") return; // user cancelled — do nothing
      console.warn("showSaveFilePicker failed:", err.message);
      // fall through to Method 2
    }
  }

  // ── Method 2: chrome.downloads with base64 data URI ─────────────────────
  // Calling directly from the popup page (not service worker) supports data: URIs.
  if (chrome.downloads) {
    try {
      const base64 = btoa(unescape(encodeURIComponent(payload)));
      const dataUrl = "data:application/json;base64," + base64;
      await new Promise((resolve, reject) => {
        chrome.downloads.download(
          { url: dataUrl, filename, saveAs: false, conflictAction: "uniquify" },
          (downloadId) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(downloadId);
            }
          }
        );
      });
      showToast("✓ Backup downloaded to Downloads folder");
      return;
    } catch (err) {
      console.warn("chrome.downloads failed:", err.message);
      // fall through to Method 3
    }
  }

  // ── Method 3: Copy to clipboard as last resort ───────────────────────────
  try {
    await navigator.clipboard.writeText(payload);
    showToast("⚠ Download unavailable — backup copied to clipboard instead");
  } catch (err) {
    showToast("Download failed. Use Copy to Clipboard button above.");
  }
}

function buildBackupPayload() {
  if (!vault || !vault.accounts) return "";
  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      accounts: vault.accounts,
      createdAt: vault.createdAt,
    },
    null,
    2,
  );
}

function populateExportBackup() {
  if (!elements.exportText) return;
  elements.exportText.value = buildBackupPayload();
  updateBackupStatus();
}

function updateBackupStatus() {
  if (!elements.backupStatus || !elements.backupDate) return;
  if (elements.exportText.value) {
    elements.backupStatus.classList.remove("hidden");
    const now = new Date();
    elements.backupDate.textContent = `Last generated: ${now.toLocaleString()}`;
  } else {
    elements.backupStatus.classList.add("hidden");
  }
}

async function handleCopyBackup() {
  const payload = buildBackupPayload();
  if (!payload) {
    showToast("No vault to backup");
    return;
  }
  await navigator.clipboard.writeText(payload);
  showToast("✓ Backup copied to clipboard");
}

async function handleImportBackup() {
  clearImportError();
  const content = elements.importText?.value?.trim();
  if (!content) {
    showImportError("Paste a backup JSON or upload a file");
    return;
  }

  showImportError("Parsing backup data... Please wait.");

  let payload;
  try {
    // Clean potential BOM or extra whitespaces
    const cleanContent = content.replace(/^\uFEFF/, "");
    payload = JSON.parse(cleanContent);
  } catch (parseError) {
    showImportError(`Invalid JSON format: ${parseError.message}`);
    console.error("JSON parse error:", parseError);
    return;
  }

  // 1. Check if it's a decrypted accounts list
  let importedAccounts = null;
  if (Array.isArray(payload)) {
    importedAccounts = payload;
  } else if (payload && Array.isArray(payload.accounts)) {
    importedAccounts = payload.accounts;
  }

  if (importedAccounts) {
    showImportError(`Found ${importedAccounts.length} decrypted accounts. Validating...`);
    // Validate accounts
    const validAccounts = importedAccounts.every(
      (account) => account && typeof account.secret === "string"
    );
    if (!validAccounts || importedAccounts.length === 0) {
      showImportError("Invalid account data in backup - secret is required for all accounts");
      return;
    }

    showImportError("Importing and encrypting accounts...");
    // Import accounts into current vault, ensuring all fields are populated correctly
    if (!vault) {
      vault = { accounts: [], createdAt: Date.now() };
    }

    // Clean and normalize secrets
    vault.accounts = importedAccounts.map((account) => ({
      id: account.id || crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`,
      issuer: account.issuer || "",
      label: account.label || "",
      secret: account.secret.replace(/\s+/g, "").toUpperCase(),
      createdAt: account.createdAt || Date.now(),
    }));

    // Re-encrypt with current PIN
    try {
      vaultRecord = await encryptVault(sessionPin, vault);
      await setVaultRecord(vaultRecord);
      clearInputs();
      showToast("✓ Backup imported successfully");
      renderAccounts();
      closeSettingsModal();
    } catch (encryptError) {
      showImportError(`Failed to encrypt and save accounts: ${encryptError.message}`);
      console.error("Encryption error:", encryptError);
    }
    return;
  }

  // 2. Check if it's an encrypted vault record
  let encryptedVault = null;
  if (payload && payload.ciphertext && payload.iv && payload.salt) {
    encryptedVault = payload;
  } else if (payload && payload.vault) {
    if (typeof payload.vault === "object" && payload.vault.ciphertext && payload.vault.iv && payload.vault.salt) {
      encryptedVault = payload.vault;
    } else if (typeof payload.vault === "string") {
      try {
        const parsedVault = JSON.parse(payload.vault);
        if (parsedVault && parsedVault.ciphertext && parsedVault.iv && parsedVault.salt) {
          encryptedVault = parsedVault;
        }
      } catch (e) {
        // ignore
      }
    }
  }

  if (encryptedVault) {
    showImportError("Found encrypted vault record. Saving directly...");
    // Save directly
    try {
      await setVaultRecord(encryptedVault);
      clearInputs();
      await setLocked(true);
      showLockedView({ createMode: false });
      closeSettingsModal();
      showToast("✓ Encrypted backup imported. Please enter PIN to unlock.");
    } catch (saveError) {
      showImportError(`Failed to save encrypted vault: ${saveError.message}`);
      console.error("Save error:", saveError);
    }
    return;
  }

  showImportError("Unrecognized backup format. Ensure the file contains accounts or vault data.");
}

function clearInputs() {
  if (elements.importText) {
    elements.importText.value = "";
  }
  if (elements.importFile) {
    elements.importFile.value = "";
  }
}

function showImportError(message) {
  if (!elements.importError) return;
  elements.importError.textContent = message;
  elements.importError.classList.remove("hidden");
}

function clearImportError() {
  if (elements.importError) {
    elements.importError.textContent = "";
    elements.importError.classList.add("hidden");
  }
}

async function handleImportFileSelect(event) {
  try {
    clearImportError();
    showImportError("Reading selected backup file...");

    const file = elements.importFile?.files?.[0] || event.target?.files?.[0];
    if (!file) {
      showImportError("No file selected.");
      return;
    }

    // Read the file content
    const content = await file.text();
    if (!content) {
      showImportError("Selected file is empty.");
      return;
    }

    // Populate textarea and trigger import
    if (elements.importText) {
      elements.importText.value = content;
    }
    await handleImportBackup();
  } catch (error) {
    console.error("File selection error:", error);
    showImportError(`Failed to read file: ${error.message || error}`);
    clearInputs();
  }
}

async function saveAccount() {
  if (!vault) return;
  elements.modalError.textContent = "";

  let secretValue = elements.secretInput.value.trim();
  const issuerValue = elements.issuerInput.value.trim();
  const labelValue = elements.labelInput.value.trim();

  if (secretValue.startsWith("otpauth://")) {
    const parsed = parseOtpauth(secretValue);
    if (parsed) {
      secretValue = parsed.secret;
      if (!elements.issuerInput.value.trim()) {
        elements.issuerInput.value = parsed.issuer;
      }
      if (!elements.labelInput.value.trim()) {
        elements.labelInput.value = parsed.label;
      }
    }
  }

  if (!secretValue) {
    elements.modalError.textContent = "Secret is required.";
    return;
  }

  const normalizedSecret = normalizeSecret(secretValue);
  try {
    base32ToBytes(normalizedSecret);
  } catch (error) {
    elements.modalError.textContent = "Secret must be valid Base32.";
    return;
  }

  const account = {
    id: editingId || crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`,
    issuer: issuerValue,
    label: labelValue,
    secret: normalizedSecret,
    createdAt:
      editingId && vault?.accounts
        ? vault.accounts.find((item) => item.id === editingId)?.createdAt ||
          Date.now()
        : Date.now(),
  };

  if (editingId) {
    vault.accounts = vault.accounts.map((item) =>
      item.id === editingId ? account : item,
    );
  } else {
    vault.accounts.unshift(account);
  }

  await saveVault();
  closeModal();
  renderAccounts();
}

// ── Drag-to-reorder handlers ─────────────────────────────────────────────────
function handleDragStart(e, accountId) {
  dragSrcId = accountId;
  // Delay adding the class so the drag image captures the normal look
  requestAnimationFrame(() => e.target.closest(".account")?.classList.add("dragging"));
  e.dataTransfer.effectAllowed = "move";
  e.dataTransfer.setData("text/plain", accountId);
}

function handleDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = "move";
  e.currentTarget.classList.add("drag-over");
}

function handleDragLeave(e) {
  e.currentTarget.classList.remove("drag-over");
}

async function handleDrop(e, targetId) {
  e.preventDefault();
  e.currentTarget.classList.remove("drag-over");
  if (!dragSrcId || dragSrcId === targetId) return;

  // Build the currently displayed order, apply the swap
  const query = elements.searchInput.value.trim().toLowerCase();
  const filtered = vault.accounts.filter(
    (a) => `${a.issuer} ${a.label}`.toLowerCase().includes(query)
  );
  const displayed = sortAccounts(filtered);

  const srcIdx = displayed.findIndex((a) => a.id === dragSrcId);
  const tgtIdx = displayed.findIndex((a) => a.id === targetId);
  if (srcIdx === -1 || tgtIdx === -1) return;

  // Reorder within the displayed slice
  const [moved] = displayed.splice(srcIdx, 1);
  displayed.splice(tgtIdx, 0, moved);

  // Rebuild vault.accounts: displayed items in new order, hidden items appended
  const hiddenIds = new Set(displayed.map((a) => a.id));
  const hidden = vault.accounts.filter((a) => !hiddenIds.has(a.id));
  vault.accounts = [...displayed, ...hidden];

  // Persist new order and switch to manual sort so it sticks
  meta = await updateMeta({ sortMode: "manual" });
  if (elements.sortSelect) elements.sortSelect.value = "manual";
  if (preferencesDraft) preferencesDraft.sortMode = "manual";

  await saveVault();
  renderAccounts();
}

function handleDragEnd(e) {
  dragSrcId = null;
  // Clean up any lingering visual states
  document.querySelectorAll(".account.dragging").forEach((el) => el.classList.remove("dragging"));
  document.querySelectorAll(".account.drag-over").forEach((el) => el.classList.remove("drag-over"));
}

function renderAccounts() {
  if (!vault) return;
  const query = elements.searchInput.value.trim().toLowerCase();
  const filtered = vault.accounts.filter((account) => {
    const haystack = `${account.issuer} ${account.label}`.toLowerCase();
    return haystack.includes(query);
  });
  const ordered = sortAccounts(filtered);

  elements.accountsList.innerHTML = "";
  elements.emptyState.classList.toggle("hidden", vault.accounts.length !== 0);

  if (ordered.length === 0) {
    return;
  }

  for (const account of ordered) {
    const item = document.createElement("div");
    item.className = "account";
    item.dataset.id = account.id;
    item.setAttribute("role", "listitem");
    item.setAttribute("draggable", "true");

    // Drag events
    item.addEventListener("dragstart", (e) => handleDragStart(e, account.id));
    item.addEventListener("dragover",  handleDragOver);
    item.addEventListener("dragleave", handleDragLeave);
    item.addEventListener("drop",      (e) => handleDrop(e, account.id));
    item.addEventListener("dragend",   handleDragEnd);

    const header = document.createElement("div");
    header.className = "account-header";

    // Drag handle — visible on hover, used to initiate drag
    const dragHandle = document.createElement("div");
    dragHandle.className = "drag-handle";
    dragHandle.setAttribute("aria-hidden", "true");
    dragHandle.innerHTML = "&#8942;&#8942;"; // ⠿ six-dot grid

    const title = document.createElement("div");
    title.className = "account-title";
    const issuer = document.createElement("strong");
    issuer.textContent = account.issuer || "Account";
    const label = document.createElement("span");
    label.textContent = account.label || "(no label)";
    title.append(issuer, label);

    const actions = document.createElement("div");
    actions.className = "actions";
    header.append(title, dragHandle);

    const codeRow = document.createElement("div");
    codeRow.className = "code-row";

    const code = document.createElement("div");
    code.className = "account-code";
    code.dataset.code = "";
    code.setAttribute("title", "Click to copy");
    code.textContent = "------";

    const ring = document.createElement("div");
    ring.className = "progress-ring";
    ring.innerHTML = `
      <svg viewBox="0 0 36 36" aria-hidden="true">
        <circle class="ring-track" cx="18" cy="18" r="15.5"></circle>
        <circle class="ring-progress" cx="18" cy="18" r="15.5"></circle>
      </svg>
      <span class="ring-text">30</span>
    `;

    codeRow.append(code, ring);
    item.append(header, codeRow);
    elements.accountsList.append(item);
  }

  currentCounter = null;
  updateCodes();
}

async function updateCodes() {
  if (!vault) return;
  const now = Date.now();
  const counter = Math.floor(now / 1000 / 30);
  if (counter === currentCounter) {
    updateProgress(now);
    return;
  }
  currentCounter = counter;

  const promises = vault.accounts.map(async (account) => {
    try {
      const otp = await generateTOTP(account.secret, now);
      codes.set(account.id, otp);
      const item = elements.accountsList.querySelector(
        `[data-id="${account.id}"]`,
      );
      if (item) {
        const codeEl = item.querySelector("[data-code]");
        codeEl.textContent = otp;
      }
    } catch (error) {
      codes.set(account.id, "------");
      const item = elements.accountsList.querySelector(
        `[data-id="${account.id}"]`,
      );
      if (item) {
        const codeEl = item.querySelector("[data-code]");
        codeEl.textContent = "------";
      }
    }
  });

  await Promise.all(promises);
  updateProgress(now);
}

function updateProgress(now = Date.now()) {
  const remaining = 30 - (Math.floor(now / 1000) % 30);
  const percent = (remaining / 30) * 100;
  const radius = 15.5;
  const circumference = 2 * Math.PI * radius;

  elements.accountsList.querySelectorAll(".progress-ring").forEach((ring) => {
    const progress = ring.querySelector(".ring-progress");
    const text = ring.querySelector(".ring-text");
    if (progress) {
      progress.style.strokeDasharray = `${circumference}`;
      progress.style.strokeDashoffset = `${circumference * (1 - percent / 100)}`;
    }
    if (text) {
      text.textContent = String(remaining);
    }
  });
}

async function handleAccountAction(event) {
  const codeTarget = event.target.closest(".account-code");
  const item = event.target.closest(".account");
  if (!item) return;
  const id = item.dataset.id;
  const account = vault.accounts.find((acc) => acc.id === id);
  if (!account) return;

  if (codeTarget) {
    const code = codes.get(id) || (await generateTOTP(account.secret));
    await navigator.clipboard.writeText(code);
    showToast("Copied");
    return;
  }

  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const action = button.dataset.action;

  if (action === "copy") {
    const code = codes.get(id) || (await generateTOTP(account.secret));
    await navigator.clipboard.writeText(code);
    showToast("Copied");
  }

  if (action === "autofill") {
    const code = codes.get(id) || (await generateTOTP(account.secret));
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (!tab?.id) return;
    chrome.tabs.sendMessage(
      tab.id,
      { type: "AUTOFILL_OTP", code },
      (response) => {
        if (chrome.runtime.lastError) {
          showToast("Autofill unavailable on this page");
          return;
        }
        if (!response?.ok) {
          showToast(response?.error || "Autofill failed");
        } else {
          showToast("Autofilled");
        }
      },
    );
  }

  if (action === "edit") {
    openModal(account);
  }

  if (action === "delete") {
    openDeleteModal(id);
  }
}

async function touchActivity() {
  if (!meta || meta.locked) return;
  const now = Date.now();
  if (now - lastActivityUpdate < 5000) return;
  lastActivityUpdate = now;
  meta = await updateMeta({ lastActive: now });
  if (sessionData) {
    sessionData.lastActive = now;
    await setSession(sessionData);
  }
}

function checkInactivity() {
  if (!meta || meta.locked) return;
  const timeoutMs = getLockTimeoutMs();
  if (timeoutMs <= 0) return;
  const now = Date.now();
  if (now - meta.lastActive > timeoutMs) {
    setLocked(true);
    showLockedView({ createMode: false });
  }
}

async function init() {
  [vaultRecord, meta, sessionData] = await Promise.all([
    getVaultRecord(),
    getMeta(),
    getSession(),
  ]);

  if (elements.lockTimeoutSelect) {
    elements.lockTimeoutSelect.value = String(getLockTimeoutMs());
  }
  if (elements.sortSelect) {
    elements.sortSelect.value = getSortMode();
  }
  applyTheme(getTheme());

  if (!vaultRecord) {
    showLockedView({ createMode: true });
  } else {
    const timeoutMs = getLockTimeoutMs();
    const lastActive = sessionData?.lastActive || meta.lastActive;
    const expired =
      timeoutMs > 0 && lastActive && Date.now() - lastActive > timeoutMs;

    if (!meta.locked && sessionData?.pin && !expired) {
      try {
        vault = await decryptVault(sessionData.pin, vaultRecord);
        sessionPin = sessionData.pin;
        await setLocked(false);
        showMainView();
      } catch (error) {
        await clearStoredSession();
        await setLocked(true);
        showLockedView({ createMode: false });
      }
    } else {
      if (expired && !meta.locked) {
        await clearStoredSession();
        await setLocked(true);
      }
      showLockedView({ createMode: false });
    }
  }

  elements.unlockBtn.addEventListener("click", handleUnlock);

  // Press Enter on any PIN field to unlock / create vault
  const onEnterUnlock = (e) => { if (e.key === "Enter") handleUnlock(); };
  elements.unlockPin.addEventListener("keydown", onEnterUnlock);
  elements.newPin.addEventListener("keydown", onEnterUnlock);
  elements.confirmPin.addEventListener("keydown", onEnterUnlock);

  elements.editAccountsBtn.addEventListener("click", openEditAccountsModal);
  elements.settingsBtn.addEventListener("click", openSettingsModal);
  elements.addAccountBtn.addEventListener("click", () => openModal());
  elements.closeModalBtn.addEventListener("click", closeModal);
  elements.cancelAccountBtn.addEventListener("click", closeModal);
  elements.saveAccountBtn.addEventListener("click", saveAccount);
  elements.closeDeleteBtn.addEventListener("click", closeDeleteModal);
  elements.cancelDeleteBtn.addEventListener("click", closeDeleteModal);
  elements.confirmDeleteBtn.addEventListener("click", confirmDelete);
  elements.closeEditAccountsBtn.addEventListener(
    "click",
    closeEditAccountsModal,
  );
  elements.closeSettingsBtn.addEventListener("click", closeSettingsModal);
  elements.settingsBackBtn.addEventListener("click", showSettingsList);
  elements.changePinBtn.addEventListener("click", handleChangePin);
  elements.backupBtn.addEventListener("click", handleBackup);
  elements.copyBackupBtn.addEventListener("click", handleCopyBackup);
  // "Open Full Backup Page" button — opens backup.html as a tab (file pickers work there)
  elements.importFileBtn?.addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("backup.html") });
  });

  // Drag-and-drop on the drop zone — no dialog, no popup close, just reads the file
  const dropZone = document.getElementById("importDropZone");
  if (dropZone) {
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-over");
    });
    dropZone.addEventListener("dragleave", () => {
      dropZone.classList.remove("drag-over");
    });
    dropZone.addEventListener("drop", async (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-over");
      const file = e.dataTransfer?.files?.[0];
      if (!file) return;
      try {
        const content = await file.text();
        if (!content) { showImportError("Dropped file is empty."); return; }
        if (elements.importText) elements.importText.value = content;
        showImportError(`✓ "${file.name}" loaded — click Import to apply.`);
      } catch (err) {
        showImportError(`Failed to read file: ${err.message}`);
      }
    });
  }

  // Also allow drag-and-drop directly onto the textarea
  if (elements.importText) {
    elements.importText.addEventListener("dragover", (e) => e.preventDefault());
    elements.importText.addEventListener("drop", async (e) => {
      e.preventDefault();
      const file = e.dataTransfer?.files?.[0];
      if (!file) return;
      try {
        const content = await file.text();
        if (content) {
          elements.importText.value = content;
          showImportError(`✓ "${file.name}" loaded — click Import to apply.`);
        }
      } catch (err) {
        showImportError(`Failed to read file: ${err.message}`);
      }
    });
  }

  elements.importBtn.addEventListener("click", handleImportBackup);
  elements.prefSaveBtn.addEventListener("click", savePreferences);
  elements.prefCancelBtn.addEventListener("click", cancelPreferences);

  // Backup tabs
  document.querySelectorAll(".backup-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const tabName = tab.dataset.tab;
      document
        .querySelectorAll(".backup-tab")
        .forEach((t) => t.classList.remove("active"));
      document
        .querySelectorAll(".backup-tab-content")
        .forEach((c) => c.classList.add("hidden"));
      tab.classList.add("active");
      const content = document.getElementById(`${tabName}-tab`);
      if (content) content.classList.remove("hidden");
    });
  });

  document.querySelectorAll(".settings-item").forEach((button) => {
    button.addEventListener("click", () => {
      const key = button.dataset.settings;
      openSettingsSection(key);
    });
  });
  elements.searchInput.addEventListener("input", renderAccounts);
  elements.accountsList.addEventListener("click", handleAccountAction);

  elements.lockTimeoutSelect.addEventListener("change", () => {
    const value = Number(elements.lockTimeoutSelect.value);
    if (!preferencesDraft) {
      preferencesDraft = {
        lockTimeoutMs: getLockTimeoutMs(),
        sortMode: getSortMode(),
        theme: getTheme(),
      };
    }
    preferencesDraft.lockTimeoutMs = Number.isFinite(value)
      ? value
      : defaultInactivityMs;
  });

  elements.themeSelect.addEventListener("change", () => {
    if (!preferencesDraft) {
      preferencesDraft = {
        lockTimeoutMs: getLockTimeoutMs(),
        sortMode: getSortMode(),
        theme: getTheme(),
      };
    }
    preferencesDraft.theme = elements.themeSelect.value;
  });

  if (elements.sortSelect) {
    elements.sortSelect.addEventListener("change", () => {
      if (!preferencesDraft) {
        preferencesDraft = {
          lockTimeoutMs: getLockTimeoutMs(),
          sortMode: getSortMode(),
          theme: getTheme(),
        };
      }
      preferencesDraft.sortMode = elements.sortSelect.value;
    });
  }

  elements.secretInput.addEventListener("blur", () => {
    const value = elements.secretInput.value.trim();
    if (value.startsWith("otpauth://")) {
      const parsed = parseOtpauth(value);
      if (parsed) {
        elements.secretInput.value = parsed.secret;
        if (!elements.issuerInput.value.trim()) {
          elements.issuerInput.value = parsed.issuer;
        }
        if (!elements.labelInput.value.trim()) {
          elements.labelInput.value = parsed.label;
        }
      }
    }
  });

  document.addEventListener("click", touchActivity);
  document.addEventListener("keydown", touchActivity);

  setInterval(() => {
    if (!meta?.locked && vault) {
      updateCodes();
      checkInactivity();
    }
  }, 1000);
}

init();
