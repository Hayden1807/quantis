document.addEventListener("DOMContentLoaded", () => {
  const profile = document.querySelector(".profile");
  const btn = document.querySelector(".profile__btn");
  const menu = document.querySelector(".profile__menu");

  if (!profile || !btn || !menu) return;

  // Sur desktop (hover: hover), on laisse le CSS gérer (aucun conflit)
  const canHover = window.matchMedia("(hover: hover) and (pointer: fine)").matches;

  const close = () => {
    profile.classList.remove("is-open");
    btn.setAttribute("aria-expanded", "false");
  };

  const open = () => {
    profile.classList.add("is-open");
    btn.setAttribute("aria-expanded", "true");
  };

  // Sur devices sans hover: toggle au clic
  btn.addEventListener("click", (e) => {
    if (canHover) return;
    e.preventDefault();
    const expanded = btn.getAttribute("aria-expanded") === "true";
    if (expanded) close(); else open();
  });

  document.addEventListener("click", (e) => {
    if (canHover) return;
    if (!profile.contains(e.target)) close();
  });

  document.addEventListener("keydown", (e) => {
    if (canHover) return;
    if (e.key === "Escape") close();
  });

  const loginPath = "/login";
  const currentPath = window.location.pathname + window.location.search;
  const loginHref = `${loginPath}?next=${encodeURIComponent(currentPath)}`;

  function applyAuthLinks(isAuthenticated) {
    const protectedLinks = document.querySelectorAll("[data-auth-required]");
    protectedLinks.forEach((link) => {
      const target =
        link.dataset.protectedHref || link.getAttribute("href");
      if (!target) return;
      link.dataset.protectedHref = target;
      link.setAttribute("href", isAuthenticated ? target : loginHref);
    });

    const loginLink = document.getElementById("loginLink");
    const heroLoginLink = document.getElementById("heroLoginLink");
    const registerLink = document.getElementById("registerLink");
    const logoutLink = document.getElementById("logoutLink");

    if (loginLink) loginLink.hidden = isAuthenticated;
    if (heroLoginLink) heroLoginLink.hidden = isAuthenticated;
    if (registerLink) registerLink.hidden = isAuthenticated;
    if (logoutLink) logoutLink.hidden = !isAuthenticated;
  }

  async function detectAuthState() {
    try {
      const res = await fetch("/api/me", { credentials: "include" });
      applyAuthLinks(res.ok);
    } catch (_) {
      applyAuthLinks(false);
    }
  }

  const logoutLink = document.getElementById("logoutLink");
  if (logoutLink) {
    logoutLink.addEventListener("click", async (e) => {
      e.preventDefault();
      try {
        await fetch("/api/logout", {
          method: "POST",
          credentials: "include",
        });
      } finally {
        window.location.href = "/login";
      }
    });
  }

  detectAuthState();
});
