/**
 * Grok Games auth.
 *
 * Default backend: one shared password, verified against a salted SHA-256
 * hash baked into this file (the password itself is not stored here).
 * After the first correct entry on a browser, a persistent unlock token is
 * stored in localStorage so the launcher and every game stay unlocked,
 * including after the browser is closed.
 *
 * To swap in an online backend later (for example Firebase, for cross-device
 * locking), implement the same methods as LocalBackend and call:
 *   GrokAuth.setBackend(yourBackend)
 *
 * Backend contract:
 *   hasDeviceLock() -> boolean
 *   linkedUsername() -> string|null
 *   createAccount(username, password) -> Promise<account>
 *     must reject with { code: "DEVICE_LOCKED", message: "This device is already linked to another account." }
 *     if this device is already bound to an account
 *   signIn(username, password) -> Promise<account>
 *     must reject with { code: "DEVICE_LOCKED" } and the same message when the
 *     username is not the one linked to this device
 *     must reject with { code: "BAD_PASSWORD" } on a wrong password
 */
(function (global) {
  "use strict";

  // Salted SHA-256 of the shared password (salt || utf8(password)).
  var SHARED_SALT = "5bc4e9078136a45961a630abf3de3bf6";
  var SHARED_HASH = "42d65c99323d830f26c443e64c0af30c56d1a7e3723fe566ff9cedc4ae812c2e";

  // v2 so pre-v1.11.3 per-user unlocks and hashes no longer count.
  var UNLOCK_KEY = "gg.unlock.v2";
  var SESSION_KEY = "gg.session";
  var LOCK_MESSAGE = "This device is already linked to another account.";

  function bytesToHex(buf) {
    var u8 = new Uint8Array(buf);
    var out = "";
    for (var i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, "0");
    return out;
  }

  function hexToBytes(hex) {
    var a = new Uint8Array(hex.length / 2);
    for (var i = 0; i < a.length; i++) a[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return a;
  }

  function concat(a, b) {
    var o = new Uint8Array(a.length + b.length);
    o.set(a, 0);
    o.set(b, a.length);
    return o;
  }

  function sha256Salted(password, saltBytes) {
    var data = concat(saltBytes, new TextEncoder().encode(password));
    return crypto.subtle.digest("SHA-256", data).then(bytesToHex);
  }

  function fail(code, message) {
    var err = new Error(message);
    err.code = code;
    return err;
  }

  function checkSharedPassword(password) {
    if (!password) return Promise.reject(fail("VALIDATION", "Enter the password."));
    return sha256Salted(password, hexToBytes(SHARED_SALT)).then(function (hash) {
      if (hash !== SHARED_HASH) return Promise.reject(fail("BAD_PASSWORD", "Incorrect password."));
      return { username: "player", at: Date.now() };
    });
  }

  var LocalBackend = {
    name: "local",

    hasDeviceLock: function () {
      return true;
    },

    linkedUsername: function () {
      return "player";
    },

    createAccount: function () {
      return Promise.reject(fail("DEVICE_LOCKED", LOCK_MESSAGE));
    },

    signIn: function (username, password) {
      var self = this;
      return checkSharedPassword(password).then(function (account) {
        return { username: self.linkedUsername() || username || "player", at: account.at };
      });
    }
  };

  var backend = LocalBackend;

  function getSession() {
    try {
      var raw = sessionStorage.getItem(SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function setSession(session) {
    if (!session) sessionStorage.removeItem(SESSION_KEY);
    else sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  }

  function getUnlock() {
    try {
      var raw = localStorage.getItem(UNLOCK_KEY);
      var u = raw ? JSON.parse(raw) : null;
      if (u && u.ok) return u;
    } catch (e) {}
    return null;
  }

  function setUnlock(session) {
    if (!session) localStorage.removeItem(UNLOCK_KEY);
    else localStorage.setItem(UNLOCK_KEY, JSON.stringify(session));
  }

  function persistUnlock(account) {
    var session = { ok: true, username: account.username || "player", at: Date.now() };
    setUnlock(session);
    setSession(session);
    return account;
  }

  function launcherUrl() {
    var scripts = document.getElementsByTagName("script");
    for (var i = 0; i < scripts.length; i++) {
      var s = scripts[i];
      var src = s.src || "";
      if (src && /auth\.js(\?.*)?$/.test(src)) {
        try { return new URL("index.html", src).href; } catch (e) {}
      }
    }
    return "../../index.html";
  }

  var GrokAuth = {
    setBackend: function (b) { backend = b; },
    getBackend: function () { return backend; },

    hasAccount: function () { return true; },

    isSignedIn: function () {
      var u = getUnlock();
      return !!(u && u.ok);
    },

    currentUser: function () {
      var u = getUnlock();
      return u && u.ok ? u.username : null;
    },

    linkedUsername: function () { return backend.linkedUsername(); },

    createAccount: function () {
      return Promise.reject(fail("DEVICE_LOCKED", LOCK_MESSAGE));
    },

    signIn: function (username, password) {
      return backend.signIn(username, password).then(persistUnlock);
    },

    enterPassword: function (password) {
      return checkSharedPassword(password).then(persistUnlock);
    },

    signOut: function () {
      // Persistent unlock stays until the user clears site data. signOut only
      // drops the leftover sessionStorage entry from the old scheme.
      setSession(null);
    },

    requireSession: function () {
      if (this.isSignedIn()) return true;
      // Chrome treats each file:// path as its own origin, so the launcher
      // unlock cannot be read from a game page. Gate only the launcher then.
      if (location.protocol === "file:") return true;
      var url = launcherUrl();
      try { location.replace(url); } catch (e) { location.href = url; }
      return false;
    }
  };

  global.GrokAuth = GrokAuth;
})(typeof window !== "undefined" ? window : this);
