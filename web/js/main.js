document.addEventListener("DOMContentLoaded", () => {
  const profile = document.querySelector(".profile");
  const btn = document.querySelector(".profile__btn");
  const menu = document.querySelector(".profile__menu");
  const defaultAvatar = "/assets/images/User.png";

  if (!profile || !btn || !menu) return;

  const canHover = window.matchMedia("(hover: hover) and (pointer: fine)").matches;

  const close = () => {
    profile.classList.remove("is-open");
    btn.setAttribute("aria-expanded", "false");
  };

  const open = () => {
    profile.classList.add("is-open");
    btn.setAttribute("aria-expanded", "true");
  };

  btn.addEventListener("click", (e) => {
    if (canHover) return;
    e.preventDefault();
    const expanded = btn.getAttribute("aria-expanded") === "true";
    if (expanded) close();
    else open();
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

  function setVisibility(el, visible) {
    if (!el) return;
    el.hidden = !visible;
    el.style.display = visible ? el.dataset.display || "" : "none";
  }

  function applyAvatar(avatarUrl) {
    const src = avatarUrl && /^https?:\/\//i.test(avatarUrl)
      ? avatarUrl
      : defaultAvatar;

    document.querySelectorAll(".profile__avatar").forEach((img) => {
      img.src = src;
    });
  }

  function applyAuthLinks(isAuthenticated) {
    const protectedLinks = document.querySelectorAll("[data-auth-required]");
    protectedLinks.forEach((link) => {
      const target = link.dataset.protectedHref || link.getAttribute("href");
      if (!target) return;
      link.dataset.protectedHref = target;
      link.setAttribute("href", isAuthenticated ? target : loginHref);
    });

    document.querySelectorAll("[data-auth-visible]").forEach((el) => {
      setVisibility(el, isAuthenticated);
    });
    document.querySelectorAll("[data-guest-visible]").forEach((el) => {
      setVisibility(el, !isAuthenticated);
    });
  }

  async function detectAuthState() {
    try {
      const res = await fetch("/api/me", { credentials: "include" });
      if (!res.ok) {
        applyAuthLinks(false);
        applyAvatar(null);
        return;
      }

      const me = await res.json();
      applyAuthLinks(true);
      applyAvatar(me.avatar_url || null);
    } catch (_) {
      applyAuthLinks(false);
      applyAvatar(null);
    }
  }

  const logoutTargets = [
    document.getElementById("logoutLink"),
    document.getElementById("logoutBtn"),
    document.getElementById("logoutCardBtn"),
  ].filter(Boolean);

  logoutTargets.forEach((target) => {
    target.addEventListener("click", async (e) => {
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
  });

  detectAuthState();
});
