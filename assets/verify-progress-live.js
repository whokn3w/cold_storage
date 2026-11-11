(() => {
  "use strict";

  const holder = document.getElementById("verify-progress-live");
  if (!holder) return;

  const drive = holder.getAttribute("data-drive-id");

  if (!drive || !/^[A-Za-z0-9._-]{1,256}$/.test(drive) ||
      drive === "." || drive === "..") return;

  const pollMarker = () =>
    holder.querySelector("[data-progress-poll]");

  // No snapshot yet: check periodically for a newly started run.
  // Completed or interrupted snapshots do not initiate polling.
  const initial = pollMarker();
  if (initial && initial.getAttribute("data-progress-poll") !== "true") {
    return;
  }

  const endpoint = "/verify-progress?id=" +
    encodeURIComponent(drive);

  const intervalMs = 10000;

  let timer = null;
  let pending = false;
  let stopped = false;

  function markUnavailable(message) {
    let notice = holder.querySelector(
      "[data-progress-refresh-notice]"
    );

    if (!notice) {
      notice = document.createElement("p");
      notice.className = "muted";
      notice.setAttribute("data-progress-refresh-notice", "");
      notice.setAttribute("role", "status");
      holder.appendChild(notice);
    }

    notice.textContent = message;
  }

  function schedule() {
    if (!stopped && timer === null) {
      timer = window.setTimeout(poll, intervalMs);
    }
  }

  async function poll() {
    timer = null;

    // Never overlap requests or poll while the tab is hidden.
    if (stopped || pending) return;

    if (document.hidden) {
      schedule();
      return;
    }

    pending = true;

    try {
      const response = await fetch(endpoint, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "text/html" }
      });

      if (response.status === 200) {
        const markup = await response.text();
        const template = document.createElement("template");
        template.innerHTML = markup;

        const panel = template.content.firstElementChild;

        if (template.content.children.length !== 1 ||
            !panel ||
            !panel.matches(
              'section[aria-label="SHA-256 verification progress"]'
            ) ||
            !panel.querySelector("[data-progress-poll]")) {
          throw new Error("Unexpected progress response");
        }

        // Replace ONLY the progress panel.
        // Drive details and historical records remain untouched.
        holder.replaceChildren(panel);

        if (pollMarker().getAttribute("data-progress-poll") !== "true") {
          stopped = true;
        }

      } else if (response.status === 204) {
        // No progress is normal before the first verification.
        // If counts already exist, preserve them with a warning.
        if (pollMarker()) {
          markUnavailable(
            "Live progress temporarily unavailable; " +
            "displayed counts may be outdated."
          );
        }

      } else if (response.status === 400 ||
                 response.status === 404) {
        markUnavailable(
          "Live progress is unavailable for this drive."
        );
        stopped = true;

      } else {
        throw new Error("Unable to refresh verification progress");
      }

    } catch (_) {
      // A failed network request must never appear as a
      // successful verification or erase the last snapshot.
      markUnavailable(
        "Live progress refresh failed; " +
        "displayed counts may be outdated."
      );

    } finally {
      pending = false;
      schedule();
    }
  }

  // When returning to this browser tab, get a fresh snapshot.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden || stopped || pending) return;

    if (timer !== null) {
      window.clearTimeout(timer);
    }

    timer = null;
    void poll();
  });

  schedule();
})();
