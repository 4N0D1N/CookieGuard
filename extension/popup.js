document.addEventListener("DOMContentLoaded", () => {
  const listEl = document.getElementById("eventsList");

  chrome.storage.local.get({ events: [] }, (data) => {
    if (!data.events || data.events.length === 0) {
      listEl.innerHTML = '<div style="color: #64748b; text-align: center; padding: 8px;">Supervisión activa. Sin cambios recientes.</div>';
      return;
    }

    listEl.innerHTML = "";
    data.events.slice(0, 15).forEach((ev) => {
      const timeStr = ev.timestamp ? ev.timestamp.split("T")[1].slice(0, 8) : "";
      const div = document.createElement("div");
      div.className = "event-item";
      div.innerHTML = `<span class="event-time">[${timeStr}]</span> <span class="event-domain">${ev.domain}</span>: ${ev.name} (${ev.removed ? 'Eliminada' : 'Modificada'})`;
      listEl.appendChild(div);
    });
  });
});
