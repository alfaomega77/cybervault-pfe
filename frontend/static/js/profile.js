/** Profile page — name, avatar, password, delete account */

(function () {
  let currentUser = null;
  let pendingAvatar = undefined; // undefined = unchanged, '' = remove, string = data URL

  function setStatus(id, message, ok) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = message || '';
    el.classList.toggle('ok', !!ok && !!message);
    el.classList.toggle('err', !ok && !!message);
  }

  function initials(user) {
    const a = (user?.first_name || '').trim().charAt(0);
    const b = (user?.last_name || '').trim().charAt(0);
    const letters = `${a}${b}`.toUpperCase();
    if (letters) return letters;
    return (user?.email || 'CV').slice(0, 2).toUpperCase();
  }

  function paintAvatarPreview(user, override) {
    const box = document.getElementById('avatar-preview');
    if (!box) return;
    const src = override !== undefined ? override : (user?.avatar || '');
    if (src) {
      box.innerHTML = `<img src="${src}" alt="">`;
    } else {
      box.textContent = initials(user || {});
      box.querySelector('img')?.remove();
    }
  }

  function fillForm(user) {
    document.getElementById('email').value = user.email || '';
    document.getElementById('first_name').value = user.first_name || '';
    document.getElementById('last_name').value = user.last_name || '';
    document.getElementById('company').value = user.company || '';
    paintAvatarPreview(user);
    if (typeof fillUserChip === 'function') fillUserChip(user);
  }

  function readFileAsDataUrl(file) {
    return new Promise((resolve, reject) => {
      if (!file) return resolve('');
      if (!/^image\/(jpeg|png|webp|gif)$/i.test(file.type)) {
        reject(new Error('Format photo invalide (JPEG, PNG, WebP ou GIF).'));
        return;
      }
      if (file.size > 120 * 1024) {
        reject(new Error('Photo trop volumineuse (max ~100 Ko).'));
        return;
      }
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(new Error('Lecture de la photo impossible.'));
      reader.readAsDataURL(file);
    });
  }

  async function boot() {
    if (!Auth.requireAuth()) return;
    document.getElementById('btn-logout')?.addEventListener('click', (e) => {
      e.preventDefault();
      Auth.logout();
    });

    currentUser = await Auth.me();
    if (!currentUser) {
      Auth.logout();
      return;
    }
    fillForm(currentUser);
    if (typeof initModeSwitch === 'function') initModeSwitch();

    document.getElementById('avatar-input')?.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      setStatus('profile-status', '', true);
      try {
        const dataUrl = await readFileAsDataUrl(file);
        pendingAvatar = dataUrl;
        paintAvatarPreview(currentUser, dataUrl);
      } catch (err) {
        setStatus('profile-status', err.message, false);
        e.target.value = '';
      }
    });

    document.getElementById('btn-remove-avatar')?.addEventListener('click', () => {
      pendingAvatar = '';
      paintAvatarPreview(currentUser, '');
      const input = document.getElementById('avatar-input');
      if (input) input.value = '';
    });

    document.getElementById('profile-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-save-profile');
      btn.disabled = true;
      setStatus('profile-status', '', true);
      try {
        const body = {
          first_name: document.getElementById('first_name').value,
          last_name: document.getElementById('last_name').value,
          company: document.getElementById('company').value,
        };
        if (pendingAvatar !== undefined) body.avatar = pendingAvatar;
        const data = await Auth.updateProfile(body);
        currentUser = data.user;
        pendingAvatar = undefined;
        fillForm(currentUser);
        setStatus('profile-status', 'Profil enregistré.', true);
        if (typeof showToast === 'function') showToast('Profil enregistré', 'success');
      } catch (err) {
        setStatus('profile-status', err.message, false);
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById('password-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-save-password');
      btn.disabled = true;
      setStatus('password-status', '', true);
      try {
        await Auth.changePassword(
          document.getElementById('current_password').value,
          document.getElementById('new_password').value,
        );
        setStatus('password-status', 'Mot de passe mis à jour. Redirection…', true);
        Auth.setToken(null);
        setTimeout(() => { window.location.href = '/login.html'; }, 800);
      } catch (err) {
        setStatus('password-status', err.message, false);
        btn.disabled = false;
      }
    });

    document.getElementById('delete-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const ok = await confirmAction(
        'Supprimer définitivement votre compte CyberVault ? Cette action est irréversible.',
        'Supprimer',
      );
      if (!ok) return;
      const btn = document.getElementById('btn-delete');
      btn.disabled = true;
      setStatus('delete-status', '', true);
      try {
        await Auth.deleteAccount(document.getElementById('delete_password').value);
        Auth.setToken(null);
        window.location.href = '/login.html';
      } catch (err) {
        setStatus('delete-status', err.message, false);
        btn.disabled = false;
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
