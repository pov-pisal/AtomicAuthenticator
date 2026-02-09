import { setVaultRecord, updateMeta, clearSession } from "./storage.js";

const elements = {
  importFileInput: document.getElementById("importFileInput"),
  importFileBtn: document.getElementById("importFileBtn"),
  importStatus: document.getElementById("importStatus"),
  closeImportBtn: document.getElementById("closeImportBtn"),
};

function setStatus(message) {
  if (elements.importStatus) {
    elements.importStatus.textContent = message;
  }
}

async function handleImport() {
  const file = elements.importFileInput?.files?.[0];
  if (!file) {
    setStatus("Select a backup file first.");
    return;
  }

  try {
    const content = await file.text();
    const payload = JSON.parse(content);
    const importedVault = payload?.vault;
    if (!importedVault || typeof importedVault !== "string") {
      setStatus("Invalid backup file.");
      return;
    }

    await setVaultRecord(importedVault);
    await clearSession();
    await updateMeta({ locked: true, lastActive: 0 });
    setStatus("Import complete. You can close this tab and unlock the vault.");
  } catch (error) {
    setStatus("Import failed. Please check the file.");
  } finally {
    if (elements.importFileInput) {
      elements.importFileInput.value = "";
    }
  }
}

function closeTab() {
  window.close();
}

elements.importFileBtn.addEventListener("click", handleImport);
elements.closeImportBtn.addEventListener("click", closeTab);
