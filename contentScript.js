function findOtpInput() {
  const candidates = Array.from(document.querySelectorAll("input"));
  const matcher = /(otp|totp|2fa|code|auth|verification|security)/i;

  return candidates.find((input) => {
    if (input.disabled || input.readOnly || input.type === "hidden") {
      return false;
    }
    const attrs = [input.name, input.id, input.placeholder, input.autocomplete]
      .filter(Boolean)
      .join(" ");
    return matcher.test(attrs) || /one-time-code/i.test(input.autocomplete || "");
  });
}

function fillInput(input, value) {
  input.focus();
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "AUTOFILL_OTP") {
    const input = findOtpInput();
    if (!input) {
      sendResponse({ ok: false, error: "No OTP input found" });
      return true;
    }
    fillInput(input, message.code);
    sendResponse({ ok: true });
    return true;
  }
  return false;
});
