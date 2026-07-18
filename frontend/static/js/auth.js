/** Auth helpers — token in localStorage */

const Auth = {
  TOKEN_KEY: 'cybervault_token',

  getToken() {
    return localStorage.getItem(this.TOKEN_KEY);
  },

  setToken(token) {
    if (token) localStorage.setItem(this.TOKEN_KEY, token);
    else localStorage.removeItem(this.TOKEN_KEY);
  },

  authHeaders() {
    const token = this.getToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  },

  async api(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    let res;
    try {
      res = await fetch(path, {
        ...options,
        signal: options.signal || controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...this.authHeaders(),
          ...(options.headers || {}),
        },
      });
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('Le service ne répond pas. Réessayez.');
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && this.getToken() && !path.endsWith('/login')) {
      this.setToken(null);
      window.location.href = '/login.html?expired=1';
      throw new Error('Votre session a expiré');
    }
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },

  async signup(form) {
    const data = await this.api('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify(form),
    });
    this.setToken(data.token);
    return data.user;
  },

  async login(email, password) {
    const data = await this.api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    this.setToken(data.token);
    return data.user;
  },

  async forgotPassword(email) {
    return this.api('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  async resetPassword(token, password) {
    return this.api('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, password }),
    });
  },

  async me() {
    try {
      return await this.api('/api/auth/me');
    } catch {
      return null;
    }
  },

  logout() {
    const token = this.getToken();
    if (token) {
      fetch('/api/auth/logout', {
        method: 'POST',
        headers: this.authHeaders(),
      }).catch(() => {});
    }
    this.setToken(null);
    window.location.href = '/login.html';
  },

  requireAuth(redirectTo = '/login.html') {
    if (!this.getToken()) {
      window.location.href = redirectTo;
      return false;
    }
    return true;
  },
};

function showAuthError(id, message) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = message;
  el.setAttribute('role', 'alert');
  el.classList.add('visible');
}

function hideAuthError(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('visible');
}
