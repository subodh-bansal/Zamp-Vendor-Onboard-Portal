(function () {
  const savedTheme = localStorage.getItem("zamp_theme");
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initialTheme = savedTheme || (prefersDark ? "dark" : "light");
  document.documentElement.setAttribute("data-theme", initialTheme);

  window.toggleTheme = function () {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("zamp_theme", next);
    updateThemeIcon();
  };

  function updateThemeIcon() {
    const btn = document.getElementById("themeToggleBtn");
    if (!btn) return;
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    btn.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
    btn.innerHTML = isDark
      ? '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
      : '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  }

  window.toggleMobileNav = function () {
    const nav = document.getElementById("mainNavLinks");
    if (nav) nav.classList.toggle("open");
  };

  window.showToast = function (title, message, linkHref, linkText) {
    const box = document.getElementById("zampToast");
    if (!box) return;
    document.getElementById("toastTitle").textContent = title || "Notification";
    document.getElementById("toastMessage").textContent = message || "";
    const footLink = document.getElementById("toastLink");
    if (linkHref) {
      footLink.href = linkHref;
      footLink.textContent = linkText || "View all";
      footLink.style.display = "inline";
    } else {
      footLink.style.display = "none";
    }
    box.classList.add("open");
  };

  window.closeToast = function () {
    const box = document.getElementById("zampToast");
    if (box) box.classList.remove("open");
  };

  window.logoutUser = async function () {
    await fetch("/auth/logout", { method: "POST" });
    window.location.href = "/";
  };

  document.addEventListener("DOMContentLoaded", updateThemeIcon);
})();