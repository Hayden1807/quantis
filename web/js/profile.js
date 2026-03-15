document.addEventListener("DOMContentLoaded", () => {
  const body = document.body;
  const defaultAvatar = "/assets/images/User.png";
  const state = {
    me: null,
    places: [],
    currentGoals: [],
  };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));

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
    if (!modal) return;
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    if (!document.querySelector(".modal.is-open")) {
      body.classList.remove("modal-open");
    }
  };

  function setBusy(button, isBusy, labelBusy = "Enregistrement...") {
    if (!button) return;
    if (!button.dataset.originalLabel) {
      button.dataset.originalLabel = button.textContent;
    }
    button.disabled = isBusy;
    button.textContent = isBusy ? labelBusy : button.dataset.originalLabel;
  }

  function redirectToLogin() {
    const next = window.location.pathname + window.location.search;
    window.location.href = `/login?next=${encodeURIComponent(next)}`;
  }

  async function apiJson(url, options = {}) {
    const response = await fetch(url, {
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      ...options,
    });

    if (response.status === 401) {
      redirectToLogin();
      throw new Error("unauthorized");
    }

    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (_) {}

    if (!response.ok) {
      throw new Error(data?.message || text || `HTTP ${response.status}`);
    }

    return data;
  }

  function applyAvatar(url) {
    const src = url && /^https?:\/\//i.test(url) ? url : defaultAvatar;
    $$(".profile__avatar").forEach((img) => {
      img.src = src;
    });
  }

  function setAlertSwitchState(isOn) {
    const sw = $("#alertEmailSwitch");
    const label = $("#alertEmailStatus");
    if (!sw) return;
    sw.classList.toggle("is-on", !!isOn);
    sw.setAttribute("aria-pressed", isOn ? "true" : "false");
    if (label) label.textContent = isOn ? "On" : "Off";
  }

  function monthlyGoalFor(goals, energy) {
    const row = Array.isArray(goals)
      ? goals.find((item) => String(item.energy || "").toLowerCase() === energy)
      : null;
    return row ? Number(row.monthly_target_kwh) || 0 : 0;
  }

  function currentPlaceId() {
    return $("#threshold-profile")?.value || "";
  }

  async function loadMe() {
    const me = await apiJson("/api/me");
    state.me = me;

    if ($("#account-email")) $("#account-email").value = me.email || "";
    if ($("#account-username")) $("#account-username").value = me.username || "";
    if ($("#account-photo")) $("#account-photo").value = me.avatar_url || "";

    applyAvatar(me.avatar_url);
    setAlertSwitchState(me.alert_email_enabled !== false);
  }

  async function loadPlaces() {
    const places = await apiJson("/api/places");
    state.places = Array.isArray(places) ? places : [];

    const select = $("#threshold-profile");
    if (!select) return;

    const previousValue = select.value;
    select.innerHTML = "";

    state.places.forEach((place) => {
      const option = document.createElement("option");
      option.value = place.id;
      option.textContent = place.name;
      select.appendChild(option);
    });

    const preferred = state.places.find((p) => p.id === previousValue) || state.places[0] || null;
    if (preferred) {
      select.value = preferred.id;
      await loadGoalsForPlace(preferred.id);
    } else {
      if ($("#threshold-elec")) $("#threshold-elec").value = "";
      if ($("#threshold-gas")) $("#threshold-gas").value = "";
    }
  }

  async function loadGoalsForPlace(placeId) {
    if (!placeId) {
      state.currentGoals = [];
      if ($("#threshold-elec")) $("#threshold-elec").value = "";
      if ($("#threshold-gas")) $("#threshold-gas").value = "";
      return;
    }

    const goals = await apiJson(`/api/places/${encodeURIComponent(placeId)}/goals`);
    state.currentGoals = Array.isArray(goals) ? goals : [];

    if ($("#threshold-elec")) {
      $("#threshold-elec").value = String(monthlyGoalFor(state.currentGoals, "electricity"));
    }
    if ($("#threshold-gas")) {
      $("#threshold-gas").value = String(monthlyGoalFor(state.currentGoals, "gas"));
    }
  }

  async function saveAccount() {
    const saveBtn = $("#saveAccountBtn");
    const email = $("#account-email")?.value.trim() || "";
    const username = $("#account-username")?.value.trim() || "";
    const avatar_url = $("#account-photo")?.value.trim() || "";

    if (!email) {
      alert("Email requis");
      return;
    }
    if (!username) {
      alert("Nom d'utilisateur requis");
      return;
    }

    setBusy(saveBtn, true);
    try {
      const me = await apiJson("/api/me", {
        method: "PUT",
        body: JSON.stringify({
          email,
          username,
          avatar_url: avatar_url || null,
        }),
      });

      state.me = me;
      applyAvatar(me.avatar_url);
      closeModal($("[data-modal='account']"));
      alert("Informations du compte mises à jour ✅");
    } catch (error) {
      if (error.message !== "unauthorized") {
        alert("Impossible d'enregistrer: " + error.message);
      }
    } finally {
      setBusy(saveBtn, false);
    }
  }

  async function saveThresholds() {
    const saveBtn = $("#saveThresholdBtn");
    const placeId = currentPlaceId();
    const elec = Number($("#threshold-elec")?.value || 0);
    const gas = Number($("#threshold-gas")?.value || 0);

    if (!placeId) {
      alert("Aucun profil sélectionné");
      return;
    }
    if (!Number.isFinite(elec) || elec < 0) {
      alert("Seuil électricité invalide");
      return;
    }
    if (!Number.isFinite(gas) || gas < 0) {
      alert("Seuil gaz invalide");
      return;
    }

    setBusy(saveBtn, true, "Sauvegarde...");
    try {
      await Promise.all([
        apiJson(`/api/places/${encodeURIComponent(placeId)}/goals`, {
          method: "PUT",
          body: JSON.stringify({
            energy: "electricity",
            weekly_kwh: elec > 0 ? elec / 4 : 0,
            monthly_kwh: elec,
          }),
        }),
        apiJson(`/api/places/${encodeURIComponent(placeId)}/goals`, {
          method: "PUT",
          body: JSON.stringify({
            energy: "gas",
            weekly_kwh: gas > 0 ? gas / 4 : 0,
            monthly_kwh: gas,
          }),
        }),
      ]);

      await loadGoalsForPlace(placeId);
      closeModal($("[data-modal='threshold']"));
      alert("Seuils enregistrés ✅");
    } catch (error) {
      if (error.message !== "unauthorized") {
        alert("Impossible d'enregistrer les seuils: " + error.message);
      }
    } finally {
      setBusy(saveBtn, false, "Sauvegarde...");
    }
  }

  async function savePassword() {
    const saveBtn = $("#savePasswordBtn");
    const current_password = $("#password-current")?.value || "";
    const new_password = $("#password-new")?.value || "";
    const confirm = $("#password-confirm")?.value || "";

    if (!current_password) {
      alert("Mot de passe actuel requis");
      return;
    }
    if (new_password.length < 10) {
      alert("Le nouveau mot de passe doit contenir au moins 10 caractères");
      return;
    }
    if (new_password !== confirm) {
      alert("Les mots de passe ne correspondent pas");
      return;
    }

    setBusy(saveBtn, true, "Mise à jour...");
    try {
      await apiJson("/api/me/password", {
        method: "PUT",
        body: JSON.stringify({ current_password, new_password }),
      });

      $("#password-current").value = "";
      $("#password-new").value = "";
      $("#password-confirm").value = "";
      closeModal($("[data-modal='security']"));
      alert("Mot de passe mis à jour ✅");
    } catch (error) {
      if (error.message !== "unauthorized") {
        alert("Impossible de changer le mot de passe: " + error.message);
      }
    } finally {
      setBusy(saveBtn, false, "Mise à jour...");
    }
  }

  async function toggleAlerts() {
    const sw = $("#alertEmailSwitch");
    if (!sw) return;

    const current = sw.getAttribute("aria-pressed") === "true";
    const next = !current;

    sw.disabled = true;
    try {
      const me = await apiJson("/api/me/preferences", {
        method: "PUT",
        body: JSON.stringify({ alert_email_enabled: next }),
      });
      state.me = me;
      setAlertSwitchState(me.alert_email_enabled !== false);
    } catch (error) {
      if (error.message !== "unauthorized") {
        alert("Impossible de modifier les alertes: " + error.message);
      }
      setAlertSwitchState(current);
    } finally {
      sw.disabled = false;
    }
  }

  async function logoutNow() {
    try {
      await fetch("/api/logout", {
        method: "POST",
        credentials: "include",
      });
    } finally {
      window.location.href = "/login";
    }
  }

  $$('[data-modal-open]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const modalId = btn.dataset.modalOpen;
      if (modalId === 'threshold') {
        await loadPlaces();
      }
      openModal(modalId);
    });
  });

  $$('[data-modal-close]').forEach((btn) => {
    btn.addEventListener('click', () => {
      closeModal(btn.closest('.modal'));
    });
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    const modal = document.querySelector('.modal.is-open');
    if (modal) closeModal(modal);
  });

  const segs = document.querySelectorAll('[data-seg]');
  segs.forEach((seg) => {
    seg.addEventListener('click', (event) => {
      const btn = event.target.closest('.seg__btn');
      if (!btn) return;
      seg.querySelectorAll('.seg__btn').forEach((item) => {
        item.classList.remove('is-active');
        item.setAttribute('aria-pressed', 'false');
      });
      btn.classList.add('is-active');
      btn.setAttribute('aria-pressed', 'true');
    });
  });

  $("#threshold-profile")?.addEventListener("change", async (event) => {
    await loadGoalsForPlace(event.target.value);
  });

  $("#saveAccountBtn")?.addEventListener("click", saveAccount);
  $("#saveThresholdBtn")?.addEventListener("click", saveThresholds);
  $("#savePasswordBtn")?.addEventListener("click", savePassword);
  $("#alertEmailSwitch")?.addEventListener("click", toggleAlerts);
  $("#logoutBtn")?.addEventListener("click", logoutNow);
  $("#logoutCardBtn")?.addEventListener("click", logoutNow);

  (async () => {
    try {
      await loadMe();
      await loadPlaces();
    } catch (error) {
      if (error.message !== "unauthorized") {
        console.error(error);
        alert("Impossible de charger la page profil: " + error.message);
      }
    }
  })();
});
