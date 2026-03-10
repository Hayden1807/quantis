document.addEventListener("DOMContentLoaded", () => {
  const body = document.body;
  const openButtons = document.querySelectorAll("[data-modal-open]");
  const closeButtons = document.querySelectorAll("[data-modal-close]");

  const openModal = (id) => {
    const modal = document.querySelector(`[data-modal="${id}"]`);
    if (!modal) return;
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
    body.classList.add("modal-open");

    const focusTarget = modal.querySelector("input, select, textarea, button");
    if (focusTarget) focusTarget.focus();
  };

  const closeModal = (modal) => {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    if (!document.querySelector(".modal.is-open")) {
      body.classList.remove("modal-open");
    }
  };

  openButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      openModal(btn.dataset.modalOpen);
    });
  });

  closeButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const modal = btn.closest(".modal");
      if (modal) closeModal(modal);
    });
  });

  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const modal = document.querySelector(".modal.is-open");
    if (modal) closeModal(modal);
  });

  const switches = document.querySelectorAll("[data-switch]");
  switches.forEach((sw) => {
    const label = sw.closest(".profileRow")?.querySelector("[data-switch-label]");

    const setState = (isOn) => {
      sw.classList.toggle("is-on", isOn);
      sw.setAttribute("aria-pressed", isOn ? "true" : "false");
      if (label) label.textContent = isOn ? "On" : "Off";
    };

    setState(sw.classList.contains("is-on"));

    sw.addEventListener("click", () => {
      const isOn = sw.getAttribute("aria-pressed") === "true";
      setState(!isOn);
    });
  });

  const segs = document.querySelectorAll("[data-seg]");
  segs.forEach((seg) => {
    seg.addEventListener("click", (e) => {
      const btn = e.target.closest(".seg__btn");
      if (!btn) return;
      seg.querySelectorAll(".seg__btn").forEach((item) => {
        item.classList.remove("is-active");
        item.setAttribute("aria-pressed", "false");
      });
      btn.classList.add("is-active");
      btn.setAttribute("aria-pressed", "true");
    });
  });
});
