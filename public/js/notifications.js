window.onload = function () {
  const urlParams = new URLSearchParams(window.location.search);
  const status = urlParams.get("status") || urlParams.get("notification");
  const message = urlParams.get("message");

  if (status && message) {
    showNotification(message, status);
    // Remove notification parameters from URL while preserving the current path
    window.history.replaceState({}, "", window.location.pathname);
  }
};

function showNotification(message, type) {
  const notification = document.createElement("div");
  // Using Unicode codes for emojis to ensure consistent rendering
  const icon = type === "success" ? "&#x2705;" : "&#x26A0;&#xFE0F;";
  notification.className = `notification ${type}`;
  notification.innerHTML = `
    <span class="notification-icon">${icon}</span>
    ${message}
  `;

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.remove();
  }, 3500);
}
