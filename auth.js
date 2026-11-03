/* Add this file to each protected Netlify site and include:
   <script src="/auth.js"></script>
   This script redirects unauthenticated visitors to School Terminal. */
(() => {
  const AUTH_ORIGIN = "https://schoolterminal.netlify.app";
  const TOKEN_KEY = "schoolterminal_auth_token";
  const API = AUTH_ORIGIN + "/api/auth";

  async function protect() {
    const params = new URLSearchParams(location.search);
    const code = params.get("auth_code");
    if (code) {
      const verifier = sessionStorage.getItem("st_pkce_verifier");
      if (!verifier) return redirectToLogin();
      try {
        const response = await fetch(API + "?action=exchange", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code, verifier })
        });
        const data = await response.json();
        if (!response.ok || !data.token) throw new Error("Could not complete login.");
        localStorage.setItem(TOKEN_KEY, data.token);
        sessionStorage.removeItem("st_pkce_verifier");
        params.delete("auth_code");
        const clean = location.pathname + (params.toString() ? "?" + params : "") + location.hash;
        history.replaceState(null, "", clean);
      } catch {
        return redirectToLogin();
      }
    }

    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      try {
        const response = await fetch(API + "?action=verify", {
          headers: { "Authorization": "Bearer " + token }
        });
        if (response.ok) return;
      } catch {}
      localStorage.removeItem(TOKEN_KEY);
    }
    redirectToLogin();
  }

  function redirectToLogin() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const verifier = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    const challengeBytes = new Uint8Array(32);
    // The server expects a SHA-256 base64url challenge.
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)).then(hash => {
      const b = new Uint8Array(hash);
      let binary = "";
      b.forEach(x => binary += String.fromCharCode(x));
      const challenge = btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
      sessionStorage.setItem("st_pkce_verifier", verifier);
      const returnTo = location.href;
      const login = new URL(AUTH_ORIGIN + "/login.html");
      login.searchParams.set("return", returnTo);
      login.searchParams.set("challenge", challenge);
      location.replace(login.toString());
    });
  }

  window.SchoolTerminalAuth = {
    logout: async () => {
      const token = localStorage.getItem(TOKEN_KEY);
      try {
        await fetch(API + "?action=logout", {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(token ? {"Authorization":"Bearer "+token} : {}) },
          body: "{}"
        });
      } finally {
        localStorage.removeItem(TOKEN_KEY);
        location.reload();
      }
    }
  };

  protect();
})();
