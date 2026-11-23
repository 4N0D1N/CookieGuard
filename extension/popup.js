document.addEventListener("DOMContentLoaded", () => {
  const listEl = document.getElementById("eventsList");

  chrome.storage.local.get({ events: [] }, (data) => {
    if (!data.events || data.events.length === 0) {
      listEl.textContent = "";
      const emptyDiv = document.createElement("div");
      emptyDiv.style.color = "#64748b";
      emptyDiv.style.textAlign = "center";
      emptyDiv.style.padding = "8px";
      emptyDiv.textContent = "Supervisión activa. Sin cambios recientes.";
      listEl.appendChild(emptyDiv);
      return;
    }

    listEl.textContent = "";
    data.events.slice(0, 15).forEach((ev) => {
      const timeStr = ev.timestamp ? ev.timestamp.split("T")[1].slice(0, 8) : "";
      const div = document.createElement("div");
      div.className = "event-item";

      const spanTime = document.createElement("span");
      spanTime.className = "event-time";
      spanTime.textContent = `[${timeStr}] `;

      const spanDomain = document.createElement("span");
      spanDomain.className = "event-domain";
      spanDomain.textContent = String(ev.domain || "");

      const spanDetails = document.createElement("span");
      spanDetails.textContent = `: ${String(ev.name || "")} (${ev.removed ? "Eliminada" : "Modificada"})`;

      div.appendChild(spanTime);
      div.appendChild(spanDomain);
      div.appendChild(spanDetails);
      listEl.appendChild(div);
    });
  });
});
