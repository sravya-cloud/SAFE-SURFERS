document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get({ events: [] }, (res) => {
    const logsDiv = document.getElementById("logs");
    logsDiv.innerHTML = res.events
      .slice(0, 10)
      .map(
        (e) => `
      <div class="log ${e.anomaly ? "anomaly" : ""}">
        [${new Date(e.timestamp).toLocaleTimeString()}] ${e.type.toUpperCase()} → 
        ${e.url ? e.url.substring(0, 50) : "inline"}
        ${e.anomaly ? " ⚠️" : ""}
      </div>`
      )
      .join("");
  });
});
