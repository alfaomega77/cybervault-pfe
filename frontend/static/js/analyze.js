/** Log file analysis + client live simulation */

let selectedFile = null;
let fileContent = null;
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

function showStep(name) {
  document.getElementById('view-choice')?.classList.toggle('hidden', name !== 'choice');
  document.getElementById('view-upload')?.classList.toggle('hidden', name !== 'upload');
  document.getElementById('view-simulate')?.classList.toggle('hidden', name !== 'simulate');
  document.getElementById('view-results')?.classList.toggle('hidden', name !== 'results');
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
        ${s.email_sent ? ' · <span style="color:#15803d;">Email envoyé</span>' : ''}
      </p>
    </div>
  `).join('');

  let mailNote = '';
  if (data.emails_sent > 0) {
    mailNote = `<p class="auth-success visible" style="display:block;">${data.emails_sent} email(s) d’alerte envoyé(s) à ${escapeHtml(data.alert_email || '—')}.</p>`;
  } else if (!data.smtp_configured) {
    mailNote = `<p style="color:var(--muted);font-size:0.9rem;">SMTP non configuré sur ce serveur — décisions visibles, pas d’email. Sur AWS, renseignez AISS_SMTP_* pour les clients.</p>`;
  } else if (!data.alert_email) {
    mailNote = `<p style="color:var(--muted);font-size:0.9rem;">Indiquez un email ci-dessus pour recevoir l’alerte de la session à risque.</p>`;
  } else {
    mailNote = `<p style="color:var(--muted);font-size:0.9rem;">Aucun email envoyé (seuil d’alerte ou erreur SMTP). Vérifiez Mon PAM → Tester l’alerte.</p>`;
  }

  box.innerHTML = `
    <p><strong>${escapeHtml(data.message || 'Simulation terminée')}</strong></p>
    ${mailNote}
    ${rows}
    <p style="margin-top:0.85rem;font-size:0.85rem;color:var(--muted);">
      Mode dry-run : ${data.dry_run ? 'oui (actions LOCK/KILL simulées, sans couper de vraie session)' : 'non (actions réelles si JumpServer token configuré)'}.
    </p>
  `;
  box.classList.remove('hidden');
  actions?.classList.remove('hidden');
}

document.addEventListener('DOMContentLoaded', async () => {
  if (!Auth.requireAuth('/login.html')) return;

  document.getElementById('btn-logout').addEventListener('click', (e) => {
    e.preventDefault();
    Auth.logout();
  });

  const me = await Auth.me();
  if (me?.email) {
    const emailInput = document.getElementById('sim-alert-email');
    if (emailInput && !emailInput.value) emailInput.value = me.email;
  }

  document.getElementById('btn-choose-batch')?.addEventListener('click', () => {
    resetUploadForm();
    showStep('upload');
  });

  document.getElementById('btn-choose-simulate')?.addEventListener('click', () => {
    document.getElementById('sim-error')?.classList.remove('visible');
    document.getElementById('sim-results')?.classList.add('hidden');
    document.getElementById('sim-actions')?.classList.add('hidden');
    showStep('simulate');
  });

  document.getElementById('btn-choose-live')?.addEventListener('click', () => {
    window.location.href = '/integrate.html';
  });

  document.getElementById('btn-back-choice')?.addEventListener('click', () => {
    resetUploadForm();
    showStep('choice');
  });

  document.getElementById('btn-back-from-sim')?.addEventListener('click', () => showStep('choice'));
  document.getElementById('btn-back-home')?.addEventListener('click', () => {
    resetUploadForm();
    showStep('choice');
  });

  document.getElementById('btn-run-simulation')?.addEventListener('click', async () => {
    const err = document.getElementById('sim-error');
    err?.classList.remove('visible');
    const btn = document.getElementById('btn-run-simulation');
    btn.disabled = true;
    btn.textContent = 'Simulation en cours…';
    try {
      const data = await Auth.api('/api/integration/demo-live', {
        method: 'POST',
        body: JSON.stringify({
          alert_email: document.getElementById('sim-alert-email')?.value?.trim() || '',
        }),
      });
      renderSimulation(data);
      showToast('Simulation live terminée', 'success');
    } catch (e) {
      if (err) {
        err.textContent = e.message;
        err.classList.add('visible');
      }
    } finally {
      btn.disabled = false;
      btn.textContent = 'Lancer la simulation →';
    }
  });

  document.getElementById('btn-sim-again')?.addEventListener('click', () => {
    document.getElementById('sim-results')?.classList.add('hidden');
    document.getElementById('sim-actions')?.classList.add('hidden');
    document.getElementById('btn-run-simulation')?.click();
  });

  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');

  document.getElementById('btn-pick-file').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => handleFile(fileInput.files[0]));

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    handleFile(e.dataTransfer.files[0]);
  });
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  document.getElementById('btn-analyze').addEventListener('click', async () => {
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

  document.getElementById('btn-analyze-another').addEventListener('click', () => {
    resetUploadForm();
    showStep('upload');
  });

  showStep('choice');
});
