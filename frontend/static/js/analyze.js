/** Log file analysis + client live simulation */

let selectedFile = null;
let fileContent = null;
let isGuest = false;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ['.json', '.jsonl', '.txt'];

function showAnalyzeError(msg) {
  const el = document.getElementById('analyze-error');
  el.textContent = msg;
  el.classList.add('visible');
}

function hideAnalyzeError() {
  document.getElementById('analyze-error').classList.remove('visible');
}

function setNavActive(which) {
  const espace = document.getElementById('nav-espace');
  const sim = document.getElementById('nav-simulate');
  const onSim = which === 'simulate';
  // Keep both links in the sidebar at all times — only toggle highlight.
  if (espace) {
    espace.classList.toggle('active', !onSim);
    if (onSim) espace.removeAttribute('aria-current');
    else espace.setAttribute('aria-current', 'page');
  }
  if (sim) {
    sim.hidden = false;
    sim.style.display = '';
    sim.classList.toggle('active', onSim);
    if (onSim) sim.setAttribute('aria-current', 'page');
    else sim.removeAttribute('aria-current');
  }
  const topbar = document.querySelector('.app-topbar strong');
  if (topbar) topbar.textContent = onSim ? 'Tester' : 'Mon espace';
}

function syncAnalyzeUrl(mode) {
  const url = new URL(window.location.href);
  if (mode === 'simulate') url.searchParams.set('mode', 'simulate');
  else url.searchParams.delete('mode');
  if (isGuest) url.searchParams.set('guest', '1');
  else url.searchParams.delete('guest');
  history.replaceState(null, '', url.pathname + url.search);
}

function showStep(name) {
  document.getElementById('view-choice')?.classList.toggle('hidden', name !== 'choice');
  document.getElementById('view-upload')?.classList.toggle('hidden', name !== 'upload');
  document.getElementById('view-simulate')?.classList.toggle('hidden', name !== 'simulate');
  document.getElementById('view-results')?.classList.toggle('hidden', name !== 'results');
  setNavActive(name === 'simulate' ? 'simulate' : 'espace');
}

function resetUploadForm() {
  selectedFile = null;
  fileContent = null;
  const fileInput = document.getElementById('file-input');
  if (fileInput) fileInput.value = '';
  document.getElementById('file-name').textContent =
    'Formats : tableau JSON [...] ou JSONL (une ligne par événement)';
  const btn = document.getElementById('btn-analyze');
  btn.disabled = true;
  btn.textContent = 'Analyser le fichier →';
  hideAnalyzeError();
}

function handleFile(file) {
  if (!file) return;
  const extension = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(extension)) {
    showAnalyzeError('Format non pris en charge. Utilisez JSON ou JSONL.');
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    showAnalyzeError('Le fichier dépasse la limite de 2 Mo.');
    return;
  }
  selectedFile = file;
  fileContent = null;
  document.getElementById('file-name').textContent = `${file.name} (${(file.size / 1024).toFixed(1)} Ko)`;
  document.getElementById('btn-analyze').disabled = true;
  hideAnalyzeError();

  const reader = new FileReader();
  reader.onload = (e) => {
    fileContent = e.target.result;
    document.getElementById('btn-analyze').disabled = false;
  };
  reader.onerror = () => showAnalyzeError('Impossible de lire ce fichier.');
  reader.readAsText(file);
}

function renderResults(data) {
  const s = data.stats || {};
  document.getElementById('results-summary').textContent =
    `${s.total || 0} événements analysés depuis « ${data.filename || 'fichier'} »`;
  document.getElementById('results-stats').innerHTML = `
    <div class="result-stat"><span class="num">${s.total || 0}</span><span class="lbl">Événements</span></div>
    <div class="result-stat"><span class="num">${s.alerts || 0}</span><span class="lbl">Alertes</span></div>
    <div class="result-stat warn"><span class="num">${s.high_risk || 0}</span><span class="lbl">Risque élevé</span></div>
  `;
  showStep('results');
}

function actionLabelFr(action) {
  const map = {
    NO_ACTION: 'Aucune',
    LOG_ONLY: 'Journal',
    ALERT_ANALYST: 'Alerte',
    LOCK_SESSION: 'Verrouiller session',
    KILL_SESSION: 'Couper session',
    CREATE_TICKET: 'Ticket',
  };
  return map[action] || action || '—';
}

function renderSimulation(data) {
  const box = document.getElementById('sim-results');
  const actions = document.getElementById('sim-actions');
  const rows = (data.sessions || []).map((s) => `
    <div class="setup-step" style="margin-top:0.7rem;">
      <h3 style="margin:0 0 0.35rem;">${escapeHtml(s.label)}</h3>
      <p style="margin:0;font-size:0.88rem;color:var(--muted);">
        <code>${escapeHtml(s.command)}</code>
      </p>
      <p style="margin:0.45rem 0 0;font-size:0.9rem;">
        Risque <strong>${s.risk_pct}%</strong> ·
        Action <strong>${escapeHtml(actionLabelFr(s.action))}</strong> ·
        Exécution <strong>${escapeHtml(s.execution_status)}</strong>
        ${s.email_sent ? ' · <span style="color:#15803d;">Inclus dans l’email</span>' : ''}
      </p>
    </div>
  `).join('');

  const delivery = data.email_delivery || {};
  const preview = data.email_preview || null;
  let mailNote = '';
  if (data.emails_sent > 0 && delivery.ok !== false) {
    mailNote = `
      <div class="auth-success visible" style="display:block;margin:0.75rem 0;">
        Email récapitulatif envoyé à <strong>${escapeHtml(data.alert_email || '—')}</strong>.
        <br><span style="font-weight:500;">Sujet :</span> ${escapeHtml(preview?.subject || '[CyberVault] Résultat de votre test')}
        <br><small>Si rien en boîte de réception sous 1–2 min : vérifiez Spam / Quarantaine.</small>
      </div>`;
  } else if (data.alert_email && delivery.ok === false) {
    mailNote = `<p class="auth-error visible" style="display:block;">Échec d’envoi SMTP vers ${escapeHtml(data.alert_email)} : ${escapeHtml(delivery.error || 'erreur inconnue')}. Les décisions restent visibles ci-dessous.</p>`;
  } else if (!data.smtp_configured) {
    mailNote = `<p style="color:var(--muted);font-size:0.9rem;">SMTP non configuré (AISS_SMTP_*). Décisions visibles ici ; configurez SMTP pour les clients.</p>`;
  } else if (!data.alert_email) {
    mailNote = `<p style="color:var(--muted);font-size:0.9rem;">Indiquez un email ci-dessus pour recevoir le récapitulatif (perso, pro ou universitaire).</p>`;
  }

  let previewBlock = '';
  if (preview?.text) {
    previewBlock = `
      <details open style="margin-top:1rem;border:1px solid var(--border);border-radius:12px;padding:0.85rem 1rem;background:#f8fafc;">
        <summary style="cursor:pointer;font-weight:700;">Aperçu de l’email envoyé (visible immédiatement)</summary>
        <pre style="white-space:pre-wrap;font-size:0.85rem;margin:0.75rem 0 0;font-family:var(--font-mono);color:#334155;">${escapeHtml(preview.text)}</pre>
      </details>`;
  }

  const decisionsLink = isGuest
    ? `<a class="btn-green" href="/signup.html?next=%2Fapp.html">Créer un compte pour garder l’historique →</a>`
    : `<a class="btn-green" href="/app.html">Voir dans Décisions →</a>`;

  box.innerHTML = `
    <p><strong>${escapeHtml(data.message || 'Test terminé')}</strong></p>
    ${mailNote}
    ${previewBlock}
    ${rows}
    <p style="margin-top:0.85rem;font-size:0.85rem;color:var(--muted);">
      Mode dry-run : ${data.dry_run ? 'oui (actions LOCK/KILL simulées, sans couper de vraie session)' : 'non (actions réelles si JumpServer token configuré)'}.
    </p>
  `;
  box.classList.remove('hidden');
  if (actions) {
    actions.innerHTML = `
      ${decisionsLink}
      <button type="button" class="btn-outline" id="btn-sim-again">Relancer</button>
    `;
    actions.classList.remove('hidden');
    document.getElementById('btn-sim-again')?.addEventListener('click', () => {
      document.getElementById('sim-results')?.classList.add('hidden');
      actions.classList.add('hidden');
      document.getElementById('btn-run-simulation')?.click();
    });
  }
}

function applyGuestChrome() {
  const logout = document.getElementById('btn-logout');
  if (logout) {
    logout.textContent = 'Créer un compte';
    logout.setAttribute('href', '/signup.html?next=%2Fanalyze.html%3Fmode%3Dsimulate');
    logout.onclick = null;
  }
  document.getElementById('guest-banner')?.classList.remove('hidden');
}

function openSimulateView({ syncUrl = true } = {}) {
  document.getElementById('sim-error')?.classList.remove('visible');
  document.getElementById('sim-results')?.classList.add('hidden');
  document.getElementById('sim-actions')?.classList.add('hidden');
  showStep('simulate');
  if (syncUrl) syncAnalyzeUrl('simulate');
}

function openEspaceView({ syncUrl = true } = {}) {
  resetUploadForm();
  showStep('choice');
  if (syncUrl) syncAnalyzeUrl('espace');
}

document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const wantSimulate = params.get('mode') === 'simulate';
  isGuest = params.get('guest') === '1' || sessionStorage.getItem('cybervault_guest') === '1';

  if (Auth.getToken()) {
    isGuest = false;
    sessionStorage.removeItem('cybervault_guest');
  } else if (wantSimulate || isGuest) {
    isGuest = true;
    sessionStorage.setItem('cybervault_guest', '1');
  } else if (!Auth.requireAuth('/login.html')) {
    return;
  }

  if (isGuest) {
    applyGuestChrome();
  } else {
    document.getElementById('btn-logout')?.addEventListener('click', (e) => {
      e.preventDefault();
      Auth.logout();
    });
  }

  const me = isGuest ? null : await Auth.me();
  if (me?.email) {
    const emailInput = document.getElementById('sim-alert-email');
    if (emailInput && !emailInput.value) emailInput.value = me.email;
  }

  // Stay on the same page so the sidebar (and Tester link) never unmounts.
  document.getElementById('nav-simulate')?.addEventListener('click', (e) => {
    e.preventDefault();
    openSimulateView();
  });
  document.getElementById('nav-espace')?.addEventListener('click', (e) => {
    e.preventDefault();
    openEspaceView();
  });

  document.getElementById('btn-choose-batch')?.addEventListener('click', () => {
    if (isGuest) {
      window.location.href = '/login.html?next=%2Fanalyze.html';
      return;
    }
    resetUploadForm();
    showStep('upload');
    syncAnalyzeUrl('espace');
  });

  document.getElementById('btn-choose-live')?.addEventListener('click', () => {
    window.location.href = isGuest
      ? '/login.html?next=%2Fintegrate.html'
      : '/integrate.html';
  });

  document.getElementById('btn-back-choice')?.addEventListener('click', () => {
    openEspaceView();
  });

  document.getElementById('btn-back-from-sim')?.addEventListener('click', () => {
    openEspaceView();
  });
  document.getElementById('btn-back-home')?.addEventListener('click', () => {
    openEspaceView();
  });

  document.getElementById('btn-run-simulation')?.addEventListener('click', async () => {
    const err = document.getElementById('sim-error');
    err?.classList.remove('visible');
    const btn = document.getElementById('btn-run-simulation');
    btn.disabled = true;
    btn.textContent = 'Test en cours…';
    try {
      const data = await Auth.api('/api/integration/demo-live', {
        method: 'POST',
        body: JSON.stringify({
          alert_email: document.getElementById('sim-alert-email')?.value?.trim() || '',
        }),
      });
      renderSimulation(data);
      showToast('Test temps réel terminé', 'success');
    } catch (e) {
      if (err) {
        err.textContent = e.message;
        err.classList.add('visible');
      }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Lancer le test →';
    }
  });

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  document.getElementById('btn-pick-file')?.addEventListener('click', () => fileInput.click());
  fileInput?.addEventListener('change', () => handleFile(fileInput.files[0]));

  dropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    handleFile(e.dataTransfer.files[0]);
  });
  dropZone?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  document.getElementById('btn-analyze')?.addEventListener('click', async () => {
    if (!fileContent) return;
    hideAnalyzeError();
    const btn = document.getElementById('btn-analyze');
    btn.disabled = true;
    btn.textContent = 'Analyse en cours…';

    try {
      const data = await Auth.api('/api/analyze/replay', {
        method: 'POST',
        body: JSON.stringify({
          jsonl: fileContent,
          filename: selectedFile?.name || 'upload.jsonl',
        }),
      });
      renderResults(data);
    } catch (err) {
      showAnalyzeError(err.message);
      btn.disabled = false;
      btn.textContent = 'Analyser le fichier →';
    }
  });

  document.getElementById('btn-analyze-another')?.addEventListener('click', () => {
    resetUploadForm();
    showStep('upload');
  });

  if (wantSimulate) {
    openSimulateView();
  } else {
    showStep('choice');
  }
});
