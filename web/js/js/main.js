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
});
