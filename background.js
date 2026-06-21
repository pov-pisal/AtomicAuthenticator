// Background service worker for Atomic Authenticator
// Currently a minimal placeholder — download is handled directly by the popup
// using chrome.downloads.download() with a Blob Object URL (popup pages have full API access).

chrome.runtime.onInstalled.addListener(() => {
  console.log("Atomic Authenticator installed.");
});
