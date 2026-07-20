/** Shared helpers for CyberVault web UI */

const API = {
  async get(path) {
    const headers = typeof Auth !== 'undefined' ? Auth.authHeaders() : {};
    const res = await fetch(path, { headers });
    if (res.status === 401 && typeof Auth !== 'undefined') {
      Auth.setToken(null);
      window.location.href = '/login.html?expired=1';
      throw new Error('Session expirée');
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return res.json();
  },
  async post(path, body) {
    const authHeaders = typeof Auth !== 'undefined' ? Auth.authHeaders() : {};
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return res.json();
  },
};

function formatTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString('fr-FR', {
      day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

function riskClass(score) {
  if (score >= 0.75) return 'status-danger';
  if (score >= 0.55) return 'status-warn';
  return 'status-ok';
}

function riskLabel(score) {
  const pct = Math.round((score || 0) * 100);
  if (pct >= 75) return `Élevé (${pct}%)`;
  if (pct >= 55) return `Moyen (${pct}%)`;
  return `Faible (${pct}%)`;
}

function actionLabel(action) {
  const map = {
    NO_ACTION: 'Aucune',
    LOG_ONLY: 'Journal',
    ALERT_ANALYST: 'Alerte',
    LOCK_SESSION: 'Verrouiller',
    KILL_SESSION: 'Couper session',
    CREATE_TICKET: 'Ticket',
  };
  return map[action] || action || '—';
}

function shorten(text, max = 80) {
  if (!text) return '—';
  const s = String(text);
  return s.length > max ? s.slice(0, max) + '…' : s;
}

function escapeHtml(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function initAppShell() {
  const toggle = document.getElementById('menu-toggle');
  const backdrop = document.getElementById('sidebar-backdrop');
  if (!toggle && !backdrop) return;

  const setOpen = (open) => {
    document.body.classList.toggle('nav-open', open);
    if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (backdrop) backdrop.setAttribute('aria-hidden', open ? 'false' : 'true');
  };

  toggle?.addEventListener('click', () => setOpen(!document.body.classList.contains('nav-open')));
  backdrop?.addEventListener('click', () => setOpen(false));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') setOpen(false);
  });
  window.addEventListener('resize', () => {
    if (window.innerWidth > 960) setOpen(false);
  });
}

function userInitials(user) {
  const a = String(user?.first_name || '').trim().charAt(0);
  const b = String(user?.last_name || '').trim().charAt(0);
  const letters = `${a}${b}`.toUpperCase();
  if (letters) return letters;
  return String(user?.email || 'CV').slice(0, 2).toUpperCase();
}

function userDisplayName(user) {
  const name = `${user?.first_name || ''} ${user?.last_name || ''}`.trim();
  return name || user?.email || 'Mon profil';
}

function fillUserChip(user) {
  if (!user) return;
  const chip = document.querySelector('.user-chip');
  if (!chip) return;

  if (chip.tagName !== 'A') {
    chip.style.cursor = 'pointer';
    chip.addEventListener('click', () => {
      window.location.href = '/profile.html';
    }, { once: true });
  } else {
    chip.setAttribute('href', '/profile.html');
  }

  let avatar = chip.querySelector('.avatar');
  if (!avatar) return;
  if (user.avatar) {
    avatar.innerHTML = `<img src="${user.avatar}" alt="">`;
    avatar.classList.add('has-photo');
  } else {
    avatar.classList.remove('has-photo');
    avatar.textContent = userInitials(user);
  }

  let meta = avatar.nextElementSibling;
  if (!meta) {
    meta = document.createElement('div');
    avatar.after(meta);
  }

  let nameEl = meta.querySelector('.user-chip-name');
  if (!nameEl) {
    nameEl = document.createElement('div');
    nameEl.className = 'user-chip-name';
    meta.prepend(nameEl);
  }
  nameEl.textContent = userDisplayName(user);

  let roleEl = meta.querySelector('.user-chip-role');
  if (!roleEl) {
    roleEl = document.createElement('div');
    roleEl.className = 'user-chip-role';
    nameEl.after(roleEl);
  }
  roleEl.textContent = (user.role || 'admin').toLowerCase() === 'admin' ? 'Admin' : (user.role || 'Admin');

  let greeting = meta.querySelector('#user-greeting') || document.getElementById('user-greeting');
  if (!greeting) {
    greeting = document.createElement('div');
    greeting.id = 'user-greeting';
    greeting.style.cssText = 'font-size:0.75rem;color:var(--muted);';
    roleEl.after(greeting);
  }
  greeting.textContent = user.email || user.company || '';
}

async function hydrateUserChip() {
  if (typeof Auth === 'undefined' || !Auth.getToken?.()) return;
  try {
    const user = await Auth.me();
    if (user) fillUserChip(user);
  } catch {
    /* ignore */
  }
}

function animateCount(el, target, duration = 520) {
  if (!el) return;
  const end = Number(target);
  if (!Number.isFinite(end)) {
    el.textContent = target ?? '—';
    return;
  }
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) {
    el.textContent = String(end);
    return;
  }
  const start = Number(el.dataset.countValue || 0);
  const startTs = performance.now();
  const tick = (now) => {
    const t = Math.min(1, (now - startTs) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    const value = Math.round(start + (end - start) * eased);
    el.textContent = String(value);
    if (t < 1) requestAnimationFrame(tick);
    else el.dataset.countValue = String(end);
  };
  requestAnimationFrame(tick);
}

document.addEventListener('DOMContentLoaded', () => {
  initAppShell();
  hydrateUserChip();
});

function showToast(message, type = 'info') {
  let region = document.getElementById('toast-region');
  if (!region) {
    region = document.createElement('div');
    region.id = 'toast-region';
    region.className = 'toast-region';
    region.setAttribute('aria-live', 'polite');
    document.body.appendChild(region);
  }
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  region.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('visible'));
  setTimeout(() => {
    toast.classList.remove('visible');
    setTimeout(() => toast.remove(), 200);
  }, 4000);
}

function confirmAction(message, confirmLabel = 'Confirmer') {
  return new Promise((resolve) => {
    const dialog = document.createElement('div');
    dialog.className = 'confirm-dialog';
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.innerHTML = `
      <div class="confirm-backdrop"></div>
      <div class="confirm-panel">
        <div class="confirm-icon" aria-hidden="true">!</div>
        <h2>Confirmer l'action</h2>
        <p></p>
        <div class="confirm-actions">
          <button type="button" class="btn btn-secondary" data-action="cancel">Annuler</button>
          <button type="button" class="btn btn-danger" data-action="confirm">${escapeHtml(confirmLabel)}</button>
        </div>
      </div>`;
    dialog.querySelector('p').textContent = message;
    const finish = (value) => {
      dialog.remove();
      resolve(value);
    };
    dialog.querySelector('[data-action="cancel"]').addEventListener('click', () => finish(false));
    dialog.querySelector('[data-action="confirm"]').addEventListener('click', () => finish(true));
    dialog.querySelector('.confirm-backdrop').addEventListener('click', () => finish(false));
    dialog.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') finish(false);
    });
    document.body.appendChild(dialog);
    dialog.querySelector('[data-action="cancel"]').focus();
  });
}

function recordContext(record) {
  const ctx = record.context || {};
  return {
    user_id: ctx.user_id || ctx.payload_username || record.user_id || record.user || record.username || '',
    account: ctx.account || record.account || '',
    asset_id: ctx.asset_id || record.asset_id || '',
    asset_name: ctx.asset_name || record.asset_name || '',
    remote_addr: ctx.remote_addr || record.remote_addr || '',
    protocol: ctx.protocol || record.protocol || '',
    command: ctx.command || '',
    hour_utc: ctx.hour_utc,
    event_timestamp: ctx.event_timestamp || (record.execution || {}).timestamp || '',
    login_type: ctx.login_type || '',
    session_commands: ctx.session_commands || [],
    source: ctx.source || record.analysis_mode || '',
    filename: ctx.filename || '',
  };
}

function displayUser(record) {
  const ctx = recordContext(record);
  if (ctx.user_id) return shorten(ctx.user_id, 28);
  if (record.session_id) return shorten(record.session_id, 14);
  return '—';
}

function displayAsset(record) {
  const ctx = recordContext(record);
  if (ctx.asset_name) return shorten(ctx.asset_name, 22);
  if (ctx.asset_id) return shorten(ctx.asset_id, 22);
  return '—';
}

function eventTypeLabel(type) {
  const map = {
    privileged_login: 'Connexion privilégiée',
    privilege_escalation: 'Élévation de privilège',
    'command.ingested': 'Commande exécutée',
    'command.acl_violation': 'Violation ACL',
    'login.failed': 'Échec de connexion',
    session_start: 'Début de session',
    session_end: 'Fin de session',
  };
  return map[type] || type || '—';
}

function humanizeReason(reason) {
  const reasonLabels = {
    ml_not_trained: 'IA ML : pas encore entraînée',
    ml_disabled: 'IA ML désactivée',
    baseline_warming_up: 'Profil en apprentissage',
    corporate_ip_whitelist: 'IP de confiance',
    login_failed: 'Échec de connexion',
    login_failed_burst: 'Rafale d\'échecs de connexion',
    high_velocity_vs_baseline: 'Activité plus rapide que d\'habitude',
  };
  if (reasonLabels[reason]) return reasonLabels[reason];
  if (reason.startsWith('unusual_hour:')) return `Heure inhabituelle (${reason.split(':')[1]}h)`;
  if (reason.startsWith('destructive_pattern:')) return 'Commande destructrice';
  if (reason.startsWith('unusual_asset:')) return `Serveur inhabituel (${reason.split(':').slice(1).join(':')})`;
  if (reason.startsWith('unusual_account:')) return `Compte inhabituel (${reason.split(':').slice(1).join(':')})`;
  if (reason.startsWith('unusual_ip:')) return `IP inhabituelle (${reason.split(':').slice(1).join(':')})`;
  if (reason.startsWith('custom_rule:')) return `Règle personnalisée : ${reason.split(':').slice(1).join(':')}`;
  if (reason.startsWith('if_score:')) return `Isolation Forest : ${reason.split(':')[1]}`;
  if (reason.startsWith('rf_score:')) return `Random Forest : ${reason.split(':')[1]}`;
  return reason;
}

function primaryReason(record) {
  const d = record.decision || {};
  const reasons = (d.reasons || []).filter((r) => r !== 'ml_not_trained');
  if (reasons.length) return humanizeReason(reasons[0]);
  if ((d.reasons || []).includes('ml_not_trained')) return 'Analyse par règles et comportement';
  return 'Aucune anomalie détectée';
}

function explainDecision(record) {
  const d = record.decision || {};
  const parts = [];
  if (d.reasons && d.reasons.length) {
    parts.push(d.reasons.map(humanizeReason).join(', '));
  }
  const xai = d.explainability;
  if (xai && xai.summary) parts.push(xai.summary);
  return parts.length ? parts.join(' · ') : '—';
}

function executionStatusLabel(status) {
  const map = {
    ok: 'Exécuté',
    dry_run: 'Simulation (mode test)',
    skipped: 'Ignoré',
    error: 'Erreur',
  };
  return map[status] || status || '—';
}

function renderEngineCard(name, engine) {
  if (!engine) return '';
  const pct = Math.round((engine.risk_score || 0) * 100);
  const reasons = (engine.reasons || [])
    .filter((r) => r !== 'ml_not_trained')
    .map(humanizeReason);
  if ((engine.reasons || []).includes('ml_not_trained')) {
    reasons.push('Modèle pas encore entraîné');
  }
  const list = reasons.length
    ? `<ul>${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>`
    : '<p class="cell-muted" style="margin:0;font-size:0.88rem;">Aucun signal</p>';
  return `<div class="engine-card">
    <h4>${escapeHtml(name)}</h4>
    <div class="score">Risque : ${pct}% · Confiance : ${Math.round((engine.confidence || 0) * 100)}%</div>
    ${list}
  </div>`;
}

function renderLoginAnalysisSection(record, loginAnalysis) {
  if (!loginAnalysis) return '';

  const severityClass = loginAnalysis.severity === 'Élevée'
    ? 'status-danger'
    : loginAnalysis.severity === 'Moyenne' ? 'status-warn' : 'status-ok';

  const alerts = (loginAnalysis.alert_reasons || [])
    .map((r) => `<li>${escapeHtml(r)}</li>`).join('');
  const steps = (loginAnalysis.investigation_steps || [])
    .map((s) => `<li>${escapeHtml(s)}</li>`).join('');

  let profileHtml = '';
  const profile = loginAnalysis.user_profile;
  if (profile) {
    profileHtml = `
      <p><strong>Profil comportemental (UEBA)</strong></p>
      <ul>
        <li>${profile.event_count} événement(s) appris</li>
        <li>Heures habituelles (UTC) : ${escapeHtml(profile.typical_hours_label)}</li>
        ${profile.known_assets.length ? `<li>Serveurs connus : ${escapeHtml(profile.known_assets.join(', '))}</li>` : ''}
        ${profile.known_accounts.length ? `<li>Comptes connus : ${escapeHtml(profile.known_accounts.join(', '))}</li>` : ''}
        ${profile.known_ips.length ? `<li>IP connues : ${escapeHtml(profile.known_ips.join(', '))}</li>` : ''}
      </ul>`;
  }

  return `
    <div class="login-detail-box">
      <h3>Connexion privilégiée — analyse détaillée</h3>
      <p>${escapeHtml(loginAnalysis.summary)}</p>
      ${alerts ? `<p><strong>Signaux détectés</strong></p><ul>${alerts}</ul>` : ''}
      <span class="severity ${severityClass}">Gravité : ${escapeHtml(loginAnalysis.severity)}</span>
      <p style="margin-top:0.75rem;"><strong>Recommandation SOC</strong><br>${escapeHtml(loginAnalysis.recommendation)}</p>
      ${profileHtml}
      <p style="margin-top:0.75rem;"><strong>Pistes d'investigation</strong></p>
      <ul>${steps}</ul>
      <div class="data-note">${escapeHtml(loginAnalysis.data_quality)}</div>
    </div>`;
}

function renderSessionActivitySection(record, activity) {
  const ctx = recordContext(record);
  const eventType = record.event_type || '';
  const isCommandEvent = eventType.includes('command') || !!ctx.command;

  let currentHtml = '';
  if (ctx.command) {
    currentHtml = `
      <h3 style="margin:1.25rem 0 0.5rem;font-size:1rem;">Commande de cet événement</h3>
      <div class="command-block">${escapeHtml(ctx.command)}</div>`;
  } else if (isCommandEvent) {
    currentHtml = `
      <h3 style="margin:1.25rem 0 0.5rem;font-size:1rem;">Commande de cet événement</h3>
      <p class="cell-muted" style="margin:0;font-size:0.9rem;">Commande non enregistrée dans les métadonnées.</p>`;
  } else {
    currentHtml = `
      <h3 style="margin:1.25rem 0 0.5rem;font-size:1rem;">Commande de cet événement</h3>
      <p class="cell-muted" style="margin:0;font-size:0.9rem;">
        Événement de type « ${escapeHtml(eventTypeLabel(eventType))} » — pas de commande shell sur cette ligne.
      </p>`;
  }

  const timeline = (activity && activity.command_timeline) || ctx.session_commands || [];
  const commands = timeline.length
    ? timeline
  : (activity && activity.commands) || [];

  let sessionHtml = '';
  if (commands.length) {
    const items = commands.map((item) => {
      const cmd = typeof item === 'string' ? item : item.command;
      const ts = typeof item === 'object' ? item.timestamp : null;
      const meta = ts ? formatTime(ts) : (typeof item === 'object' ? eventTypeLabel(item.event_type) : '');
      return `<li>
        <span>${escapeHtml(cmd)}</span>
        ${meta ? `<span class="cmd-meta">${escapeHtml(meta)}</span>` : ''}
      </li>`;
    }).join('');
    sessionHtml = `
      <h3 style="margin:1.25rem 0 0.5rem;font-size:1rem;">Historique des commandes (session)</h3>
      <ul class="command-list">${items}</ul>`;
  } else if (activity && activity.events && activity.events.length > 1) {
    const evItems = activity.events.map((ev) => `
      <li>
        <span>${escapeHtml(eventTypeLabel(ev.event_type))}${ev.command ? ' — ' + escapeHtml(ev.command) : ''}</span>
        <span class="cmd-meta">${escapeHtml(formatTime(ev.timestamp))}</span>
      </li>`).join('');
    sessionHtml = `
      <h3 style="margin:1.25rem 0 0.5rem;font-size:1rem;">Activité de la session</h3>
      <ul class="command-list">${evItems}</ul>`;
  } else {
    sessionHtml = `
      <h3 style="margin:1.25rem 0 0.5rem;font-size:1rem;">Historique des commandes (session)</h3>
      <p class="cell-muted" style="margin:0;font-size:0.9rem;">
        Aucune commande enregistrée pour cette session. Les connexions privilégiées n'incluent pas de commande shell —
        uploadez des événements <code>command.ingested</code> ou connectez JumpServer en live pour voir les commandes.
      </p>`;
  }

  return currentHtml + sessionHtml;
}

function renderDecisionDetail(record, detail) {
  const activity = detail?.session || detail;
  const loginAnalysis = detail?.login_analysis;
  const ctx = recordContext(record);
  const d = record.decision || {};
  const ex = record.execution || {};
  const asset = ctx.asset_name || ctx.asset_id || '—';
  const engines = d.engines || {};

  const fields = [
    ['Utilisateur', ctx.user_id || '—'],
    ['Compte privilégié', ctx.account || '—'],
    ['IP source', ctx.remote_addr || '—'],
    ['Asset / serveur', asset],
    ['Protocole', ctx.protocol || '—'],
    ['Type d\'événement', eventTypeLabel(record.event_type)],
    ['Heure (UTC)', ctx.hour_utc != null ? `${ctx.hour_utc}h` : formatTime(ctx.event_timestamp)],
    ['Session', record.session_id || '—'],
    ['ID événement', record.event_id || '—'],
    ['Mode', record.analysis_mode === 'historical' ? 'Analyse de logs' : 'Temps réel'],
    ['Risque global', riskLabel(d.risk_score)],
    ['Niveau', d.risk_level || '—'],
    ['Confiance', `${Math.round((d.confidence || 0) * 100)}%`],
    ['Action', actionLabel(d.action)],
    ['Exécution', `${executionStatusLabel(ex.status)}${ex.detail ? ' — ' + ex.detail : ''}`],
  ];

  if (ctx.command) fields.splice(8, 0, ['Commande', ctx.command]);

  const grid = fields.map(([label, val]) => `
    <div class="detail-item">
      <label>${escapeHtml(label)}</label>
      <span>${escapeHtml(val)}</span>
    </div>`).join('');

  const engineHtml = `
    <h3 style="margin:1.25rem 0 0.5rem;font-size:1rem;">Analyse par moteur</h3>
    <div class="engine-cards">
      ${renderEngineCard('Règles', engines.rules)}
      ${renderEngineCard('UEBA (comportement)', engines.ueba)}
      ${renderEngineCard('Machine Learning', engines.ml)}
    </div>`;

  const xai = d.explainability;
  const xaiHtml = xai && xai.summary
    ? `<p style="margin-top:1rem;color:var(--muted);font-size:0.9rem;"><strong>Explication IA :</strong> ${escapeHtml(xai.summary)}</p>`
    : '';

  const ts = ex.timestamp || record.timestamp;
  return `
    <h2 id="detail-title" style="margin:0 2rem 0 0;font-size:1.25rem;">Détail de l'événement</h2>
    <p class="cell-muted" style="margin:0.35rem 0 0;font-size:0.9rem;">${escapeHtml(formatTime(ts))} · ID ${escapeHtml(record.event_id || '—')}</p>
    <div class="detail-grid">${grid}</div>
    ${renderLoginAnalysisSection(record, loginAnalysis)}
    ${renderSessionActivitySection(record, activity)}
    ${engineHtml}
    ${xaiHtml}
    <p style="margin-top:1rem;font-size:0.88rem;color:var(--muted);">${escapeHtml(explainDecision(record))}</p>`;
}

function exportDecisionsCsv(records, filename = 'cybervault-decisions.csv') {
  const headers = [
    'Heure', 'Utilisateur', 'IP', 'Asset', 'Compte', 'Protocole', 'Type',
    'Risque %', 'Action', 'Raison', 'Session', 'Mode',
  ];
  const rows = records.map((r) => {
    const ctx = recordContext(r);
    const d = r.decision || {};
    const ts = r.execution?.timestamp || r.timestamp || '';
    return [
      ts,
      ctx.user_id,
      ctx.remote_addr,
      ctx.asset_name || ctx.asset_id,
      ctx.account,
      ctx.protocol,
      eventTypeLabel(r.event_type),
      Math.round((d.risk_score || 0) * 100),
      actionLabel(d.action),
      primaryReason(r),
      r.session_id || '',
      r.analysis_mode === 'historical' ? 'historique' : 'live',
    ];
  });
  const csv = [headers, ...rows]
    .map((row) => row.map((cell) => `"${String(cell ?? '').replace(/"/g, '""')}"`).join(','))
    .join('\n');
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

/** Sidebar Test / Live action mode (dry-run vs real LOCK/KILL). */
function paintModeSwitch(cfg = {}) {
  const root = document.getElementById('mode-switch');
  if (!root) return;
  const dry = cfg.dry_run !== false;
  const locked = !!cfg.dry_run_env_locked;
  const testBtn = document.getElementById('mode-btn-test');
  const liveBtn = document.getElementById('mode-btn-live');
  const hint = document.getElementById('mode-switch-hint');
  testBtn?.classList.toggle('active', dry);
  liveBtn?.classList.toggle('active', !dry);
  if (locked) {
    liveBtn && (liveBtn.disabled = true);
    if (hint) {
      hint.textContent = 'Verrouillé par le serveur (AISS_DRY_RUN=true)';
    }
  } else {
    liveBtn && (liveBtn.disabled = false);
    if (hint) {
      hint.textContent = dry
        ? 'Test — décisions sans kill réel'
        : 'Live — LOCK/KILL réels si JumpServer configuré';
    }
  }
  root.hidden = false;
}

async function setActionMode(mode) {
  const wantLive = mode === 'live';
  if (wantLive) {
    const ok = await confirmAction(
      'Passer en mode Live ? CyberVault pourra verrouiller ou couper de vraies sessions JumpServer si le token est configuré.',
      'Activer Live',
    );
    if (!ok) return;
  }
  const data = await Auth.api('/api/config', {
    method: 'POST',
    body: JSON.stringify({ dry_run: !wantLive }),
  });
  paintModeSwitch(data.config || data);
  if (typeof showToast === 'function') {
    showToast(wantLive ? 'Mode Live activé' : 'Mode Test (dry-run) activé', wantLive ? 'warn' : 'success');
  }
}

async function initModeSwitch() {
  const root = document.getElementById('mode-switch');
  if (!root || typeof Auth === 'undefined' || !Auth.getToken()) return;
  try {
    const cfg = await Auth.api('/api/config');
    paintModeSwitch(cfg);
  } catch {
    return;
  }
  document.getElementById('mode-btn-test')?.addEventListener('click', () => setActionMode('test'));
  document.getElementById('mode-btn-live')?.addEventListener('click', () => setActionMode('live'));
}

document.addEventListener('DOMContentLoaded', () => {
  initModeSwitch();
});

