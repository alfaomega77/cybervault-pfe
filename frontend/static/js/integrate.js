/** Mon PAM — URL + token → connect (succès ou message d’erreur) */

function showView(name) {
  document.getElementById('view-main')?.classList.toggle('hidden', name !== 'main');
  document.getElementById('view-progress')?.classList.toggle('hidden', name !== 'progress');
}

function showConnectError(msg) {
  const el = document.getElementById('connect-error');
  if (!el) return;
  if (!msg) {
    el.textContent = '';
    el.classList.remove('visible');
    return;
  }
  el.textContent = msg;
  el.classList.add('visible');
}

function loadAlertSettings(cfg) {
  const email = document.getElementById('alert_email');
  const ne = document.getElementById('notify_email');
  if (email) email.value = cfg.alert_email || '';
  if (ne) ne.checked = cfg.notify_email !== false;
}

function setConnectedUI(cfg, message) {
  const icon = document.getElementById('status-icon');
  const lead = document.getElementById('status-lead');
  const line = document.getElementById('status-line');
  const btn = document.getElementById('btn-integrate');
  const stop = document.getElementById('btn-stop-pam');

  if (icon) {
    icon.textContent = '✓';
    icon.classList.add('ok');
  }
  if (lead) lead.textContent = 'JumpServer connecté — synchronisation active';
  if (line) {
    line.textContent = message || `JumpServer : ${cfg.jumpserver_url || '—'}`;
    line.classList.remove('hidden');
  }
  if (btn) btn.textContent = 'Connecter';
  stop?.classList.remove('hidden');
}

async function saveAlerts(e) {
  e.preventDefault();
  const status = document.getElementById('alerts-status');
  const btn = document.getElementById('btn-save-alerts');
  if (btn) btn.disabled = true;
  try {
    await Auth.api('/api/config', {
      method: 'POST',
      body: JSON.stringify({
        alert_email: document.getElementById('alert_email').value.trim(),
        notify_email: document.getElementById('notify_email').checked,
      }),
    });
    if (status) status.textContent = 'Alertes enregistrées.';
  } catch (err) {
    if (status) status.textContent = 'Erreur : ' + err.message;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function testAlert() {
  const status = document.getElementById('alerts-status');
  const btn = document.getElementById('btn-test-alert');
  if (btn) btn.disabled = true;
  try {
    await saveAlerts({ preventDefault: () => {} });
    const r = await Auth.api('/api/integration/test-alert', { method: 'POST', body: '{}' });
    const emailRes = r.notification && r.notification.email;
    let msg = r.message || 'Test terminé.';
    if (emailRes && emailRes.ok) msg = 'Email envoyé à ' + emailRes.to;
    else if (emailRes && emailRes.error === 'smtp_not_configured') {
      msg = 'SMTP non configuré — alerte sauvegardée localement.';
    }
    if (status) status.textContent = msg;
  } catch (err) {
    if (status) status.textContent = 'Erreur : ' + err.message;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function integratePam() {
  showConnectError('');
  showView('progress');
  const url = (document.getElementById('jumpserver_url').value || '').trim();
  const token = (document.getElementById('jumpserver_token').value || '').trim();
  if (!url || !token) {
    showView('main');
    showConnectError('URL et token JumpServer sont requis.');
    return;
  }

  try {
    await saveAlerts({ preventDefault: () => {} });
    const r = await Auth.api('/api/integration/connect', {
      method: 'POST',
      body: JSON.stringify({ jumpserver_url: url, jumpserver_token: token }),
    });
    showView('main');
    setConnectedUI(r.config, r.message);
    showToast('JumpServer connecté', 'success');
  } catch (err) {
    showView('main');
    showConnectError(err.message || 'Connexion impossible.');
    showToast(err.message || 'Connexion échouée', 'error');
  }
}

async function stopPam() {
  if (!await confirmAction('Arrêter la surveillance temps réel ?', 'Arrêter')) return;
  await Auth.api('/api/integration/stop', { method: 'POST', body: '{}' });
  window.location.reload();
}

document.addEventListener('DOMContentLoaded', async () => {
  if (!Auth.requireAuth()) return;

  const user = await Auth.me();
  if (user) {
    document.getElementById('user-greeting').textContent =
      ((user.first_name || '') + ' ' + (user.company || user.email)).trim();
  }

  document.getElementById('btn-logout')?.addEventListener('click', (e) => {
    e.preventDefault();
    Auth.logout();
  });

  let cfg = {};
  try {
    cfg = await Auth.api('/api/config');
    if (cfg.jumpserver_url) {
      document.getElementById('jumpserver_url').value = cfg.jumpserver_url;
    }
    if (cfg.jumpserver_token_configured) {
      const tokenInput = document.getElementById('jumpserver_token');
      tokenInput.required = false;
      tokenInput.placeholder = 'Token déjà enregistré — laisser vide pour le conserver';
    }
    loadAlertSettings(cfg);

    if (cfg.pam_live_active && cfg.integration_complete) {
      setConnectedUI(cfg);
    }
  } catch (e) {
    console.warn('Config load failed', e);
  }

  document.getElementById('integrate-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    integratePam();
  });
  document.getElementById('alerts-form')?.addEventListener('submit', saveAlerts);
  document.getElementById('btn-test-alert')?.addEventListener('click', testAlert);
  document.getElementById('btn-stop-pam')?.addEventListener('click', stopPam);

  showView('main');
});
