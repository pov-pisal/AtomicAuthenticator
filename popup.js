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
  demoToggle: document.getElementById("demoToggle"),
  demoBtn: document.getElementById("demoBtn"),
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
  settingsChangePin: document.getElementById("settingsChangePin"),
  settingsBackup: document.getElementById("settingsBackup"),
  settingsPreferences: document.getElementById("settingsPreferences"),
  themeSelect: document.getElementById("themeSelect"),
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

function applyTheme(theme) {
  const resolved = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = resolved;
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
  toggleDemoButton();
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
  vault.accounts.forEach((account) => {
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
  elements.demoToggle.checked = Boolean(meta?.demoEnabled);
  elements.lockTimeoutSelect.value = String(getLockTimeoutMs());
  if (elements.themeSelect) {
    elements.themeSelect.value = getTheme();
  }
  preferencesDraft = {
    lockTimeoutMs: getLockTimeoutMs(),
    demoEnabled: Boolean(meta?.demoEnabled),
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
      demoEnabled: Boolean(meta?.demoEnabled),
      theme: getTheme(),
    };
    elements.lockTimeoutSelect.value = String(preferencesDraft.lockTimeoutMs);
    elements.demoToggle.checked = preferencesDraft.demoEnabled;
    if (elements.themeSelect) {
      elements.themeSelect.value = preferencesDraft.theme;
    }
  }
}

async function savePreferences() {
  if (!preferencesDraft) return;
  meta = await updateMeta({
    lockTimeoutMs: preferencesDraft.lockTimeoutMs,
    demoEnabled: preferencesDraft.demoEnabled,
    theme: preferencesDraft.theme,
  });
  if (sessionData) {
    sessionData.lastActive = Date.now();
    await setSession(sessionData);
  }
  toggleDemoButton();
  applyTheme(preferencesDraft.theme);
  showToast("Preferences saved");
}

function cancelPreferences() {
  preferencesDraft = {
    lockTimeoutMs: getLockTimeoutMs(),
    demoEnabled: Boolean(meta?.demoEnabled),
    theme: getTheme(),
  };
  elements.lockTimeoutSelect.value = String(preferencesDraft.lockTimeoutMs);
  elements.demoToggle.checked = preferencesDraft.demoEnabled;
  if (elements.themeSelect) {
    elements.themeSelect.value = preferencesDraft.theme;
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

function toggleDemoButton() {
  if (meta?.demoEnabled) {
    elements.demoBtn.classList.remove("hidden");
    elements.demoBtn.setAttribute("aria-hidden", "false");
  } else {
    elements.demoBtn.classList.add("hidden");
    elements.demoBtn.setAttribute("aria-hidden", "true");
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

function handleBackup() {
  if (!vaultRecord) {
    showToast("No vault to backup");
    return;
  }
  const payload = {
    exportedAt: new Date().toISOString(),
    vault: vaultRecord,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "atomic-authenticator-backup.json";
  link.click();
  URL.revokeObjectURL(url);
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

function renderAccounts() {
  if (!vault) return;
  const query = elements.searchInput.value.trim().toLowerCase();
  const filtered = vault.accounts.filter((account) => {
    const haystack = `${account.issuer} ${account.label}`.toLowerCase();
    return haystack.includes(query);
  });

  elements.accountsList.innerHTML = "";
  elements.emptyState.classList.toggle("hidden", vault.accounts.length !== 0);

  if (filtered.length === 0) {
    return;
  }

  for (const account of filtered) {
    const item = document.createElement("div");
    item.className = "account";
    item.dataset.id = account.id;
    item.setAttribute("role", "listitem");

    const header = document.createElement("div");
    header.className = "account-header";

    const title = document.createElement("div");
    title.className = "account-title";
    const issuer = document.createElement("strong");
    issuer.textContent = account.issuer || "Account";
    const label = document.createElement("span");
    label.textContent = account.label || "(no label)";
    title.append(issuer, label);

    const actions = document.createElement("div");
    actions.className = "actions";
    header.append(title);

    const codeRow = document.createElement("div");
    codeRow.className = "code-row";

    const code = document.createElement("div");
    code.className = "account-code";
    code.dataset.code = "";
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
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  const item = button.closest(".account");
  if (!item) return;
  const id = item.dataset.id;
  const account = vault.accounts.find((acc) => acc.id === id);
  if (!account) return;

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
  if (elements.demoToggle) {
    elements.demoToggle.checked = Boolean(meta?.demoEnabled);
    toggleDemoButton();
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
  elements.prefSaveBtn.addEventListener("click", savePreferences);
  elements.prefCancelBtn.addEventListener("click", cancelPreferences);
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
        demoEnabled: Boolean(meta?.demoEnabled),
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
        demoEnabled: Boolean(meta?.demoEnabled),
        theme: getTheme(),
      };
    }
    preferencesDraft.theme = elements.themeSelect.value;
  });

  elements.demoToggle.addEventListener("change", () => {
    if (!preferencesDraft) {
      preferencesDraft = {
        lockTimeoutMs: getLockTimeoutMs(),
        demoEnabled: Boolean(meta?.demoEnabled),
        theme: getTheme(),
      };
    }
    preferencesDraft.demoEnabled = elements.demoToggle.checked;
  });

  elements.demoBtn.addEventListener("click", () => {
    elements.secretInput.value = "JBSWY3DPEHPK3PXP";
    elements.issuerInput.value = "Demo";
    elements.labelInput.value = "demo@example.com";
  });

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
