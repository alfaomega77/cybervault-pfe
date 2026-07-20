/** Dashboard — client-ready security decisions view */

let pollTimer = null;
let displayLimit = 30;
let alertsOnly = false;
let searchQuery = '';
let allDecisions = [];
let detailTrigger = null;

function renderStats(data) {
  const stats = data.stats || {};
  animateCount(document.getElementById('stat-total'), stats.total ?? 0);
  const hint = document.getElementById('stat-total-hint');
  if (hint) {
    const unique = stats.unique_events ?? stats.total ?? 0;
    hint.textContent = `dont ${unique} événement${unique > 1 ? 's' : ''} unique${unique > 1 ? 's' : ''}`;
  }
  animateCount(document.getElementById('stat-alerts'), stats.alerts_24h ?? 0);
  animateCount(document.getElementById('stat-high'), stats.high_risk ?? 0);
  document.getElementById('stat-last').textContent = formatTime(stats.last_activity);
}

function updateDecisionsSubtitle(data) {
  const el = document.getElementById('decisions-subtitle');
  if (!el) return;
  const total = data.stats?.total ?? 0;
  const shown = filteredDecisions().length;
  const loaded = allDecisions.length;
  const filterNote = alertsOnly ? ' — alertes uniquement' : '';
  const searchNote = searchQuery ? ' — recherche active' : '';
  el.textContent = `${shown} ligne(s) affichée(s) sur ${loaded} chargées (${total} au total)${filterNote}${searchNote}. Cliquez sur une ligne pour le détail.`;
}

function renderIntegrationBar(status, stats) {
  const pam = document.getElementById('int-pam');
  const mode = document.getElementById('int-mode');
  const last = document.getElementById('int-last');
  if (!pam) return;

  if (status.pam_live_active) {
    pam.textContent = status.jumpserver_url || 'JumpServer connecté';
    mode.textContent = 'Live actif';
  } else if (status.integration_complete) {
    pam.textContent = status.jumpserver_url || 'JumpServer configuré';
    mode.textContent = 'Live en attente';
  } else {
    pam.textContent = 'Non connecté';
    mode.textContent = 'Fichier batch seulement';
  }

  const kicker = document.getElementById('page-kicker');
  const liveDot = document.getElementById('live-kicker-dot');
  if (kicker && liveDot) {
    liveDot.classList.toggle('hidden', !status.pam_live_active);
    const label = status.pam_live_active ? 'Live JumpServer' : 'Journal des décisions';
    kicker.replaceChildren(liveDot, document.createTextNode(' ' + label));
  }
  if (last) last.textContent = formatTime(stats?.last_activity);
}

function renderStatus(status) {
  const svc = document.getElementById('service-status');
  const mode = document.getElementById('mode-status');
  const svcMobile = document.getElementById('service-status-mobile');
  if (status.service_ok) {
    svc.textContent = status.pam_live_active ? 'Surveillance live' : 'Service actif';
    svc.className = 'status-pill status-ok';
  } else {
    svc.textContent = 'Service indisponible';
    svc.className = 'status-pill status-danger';
  }
  if (svcMobile) {
    svcMobile.textContent = svc.textContent;
    svcMobile.className = svc.className;
  }
  if (status.dry_run) {
    mode.textContent = 'Mode test';
    mode.className = 'status-pill status-warn';
  } else {
    mode.textContent = 'Production';
    mode.className = 'status-pill status-danger';
  }

  const liveBanner = document.getElementById('pam-live-banner');
  const liveText = document.getElementById('pam-live-text');
  if (liveBanner) {
    if (status.pam_live_active) {
      liveBanner.classList.remove('hidden');
      const url = status.jumpserver_url ? ` — ${status.jumpserver_url}` : '';
      liveText.textContent = `● Surveillance temps réel active${url}`;
    } else {
      liveBanner.classList.add('hidden');
    }
  }

  const banner = document.getElementById('onboarding-banner');
  if (banner) {
    if (!status.pam_live_active && !status.integration_complete) {
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }
  }
}

function matchesSearch(record) {
  if (!searchQuery) return true;
  const q = searchQuery.toLowerCase();
  const ctx = recordContext(record);
  const haystack = [
    ctx.user_id, ctx.remote_addr, ctx.asset_id, ctx.asset_name,
    ctx.account, ctx.protocol, ctx.command, record.event_type,
    eventTypeLabel(record.event_type), record.session_id, primaryReason(record),
  ].join(' ').toLowerCase();
  return haystack.includes(q);
}

function filteredDecisions() {
  return allDecisions.filter(matchesSearch);
}

function renderDecisions() {
  const tbody = document.getElementById('decisions-body');
  const decisions = filteredDecisions();

  if (!decisions.length) {
    tbody.innerHTML = `
      <tr><td colspan="9" class="empty-state">
        <strong>${searchQuery ? 'Aucun résultat pour cette recherche.' : 'Aucune décision pour l\'instant.'}</strong><br>
        <span style="font-size:0.9rem;display:inline-block;margin-top:0.35rem;">
          ${searchQuery
            ? 'Essayez un autre terme (utilisateur, IP, asset…).'
            : 'Connectez votre PAM ou <a href="/analyze.html">analysez un fichier de logs</a>.'}
        </span>
      </td></tr>`;
    return;
  }

  tbody.innerHTML = decisions.map((r, idx) => {
    const d = r.decision || {};
    const score = d.risk_score || 0;
    const ts = r.execution?.timestamp || r.timestamp;
    const ctx = recordContext(r);
    const ip = ctx.remote_addr || '—';
    const account = ctx.account || '—';
    return `<tr class="decision-row" data-idx="${idx}" tabindex="0">
      <td data-label="Heure">${formatTime(ts)}</td>
      <td class="cell-mono" data-label="Utilisateur">${escapeHtml(displayUser(r))}</td>
      <td class="cell-mono" data-label="IP source">${escapeHtml(ip)}</td>
      <td data-label="Asset">${escapeHtml(displayAsset(r))}</td>
      <td data-label="Compte">${escapeHtml(account)}</td>
      <td data-label="Type">${escapeHtml(eventTypeLabel(r.event_type))}</td>
      <td data-label="Risque"><span class="risk-meter" title="${Math.round(score * 100)}%">
        <span class="risk-bar" aria-hidden="true"><span style="width:${Math.min(100, Math.round(score * 100))}%"></span></span>
        <span class="status-pill ${riskClass(score)}">${riskLabel(score)}</span>
      </span></td>
      <td data-label="Action"><strong>${actionLabel(d.action)}</strong></td>
      <td class="reason-cell cell-muted" data-label="Raison">${escapeHtml(shorten(primaryReason(r), 70))}</td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('.decision-row').forEach((row) => {
    const idx = Number(row.dataset.idx);
    const open = () => openDetail(decisions[idx]);
    row.addEventListener('click', open);
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        open();
      }
    });
  });
}

function openDetail(record) {
  const modal = document.getElementById('detail-modal');
  const content = document.getElementById('detail-content');
  if (!modal || !content || !record) return;
  content.innerHTML = '<p class="cell-muted">Chargement…</p>';
  detailTrigger = document.activeElement;
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  document.getElementById('detail-close')?.focus();

  const eventId = record.event_id;
  if (!eventId) {
    content.innerHTML = renderDecisionDetail(record, null);
    return;
  }

  API.get(`/api/events/${encodeURIComponent(eventId)}/detail`)
    .then((data) => {
      if (!data.ok) throw new Error(data.error || 'Introuvable');
      content.innerHTML = renderDecisionDetail(data.record || record, data);
    })
    .catch(() => {
      content.innerHTML = renderDecisionDetail(record, null);
    });
}

function closeDetail() {
  document.getElementById('detail-modal')?.classList.add('hidden');
  document.body.style.overflow = '';
  detailTrigger?.focus();
  detailTrigger = null;
}

function decisionsUrl() {
  const params = new URLSearchParams({ limit: String(displayLimit) });
  if (alertsOnly) params.set('alerts_only', '1');
  return `/api/decisions?${params}`;
}

function updateFilterButtons() {
  const allBtn = document.getElementById('btn-filter-all');
  const alertsBtn = document.getElementById('btn-filter-alerts');
  const loadBtn = document.getElementById('btn-load-more');
  if (allBtn) {
    allBtn.classList.toggle('btn-primary', !alertsOnly);
    allBtn.classList.toggle('active', !alertsOnly);
  }
  if (alertsBtn) {
    alertsBtn.classList.toggle('btn-primary', alertsOnly);
    alertsBtn.classList.toggle('active', alertsOnly);
  }
  if (loadBtn) {
    if (displayLimit >= 500) {
      loadBtn.textContent = 'Maximum (500)';
      loadBtn.disabled = true;
    } else {
      loadBtn.disabled = false;
      loadBtn.textContent = displayLimit < 100 ? 'Voir plus (100)' : 'Voir tout (500)';
    }
  }
}

async function refresh() {
  try {
    const [status, decisions] = await Promise.all([
      API.get('/api/status'),
      API.get(decisionsUrl()),
    ]);
    allDecisions = decisions.decisions || [];
    renderStatus(status);
    renderStats(decisions);
    renderIntegrationBar(status, decisions.stats);
    renderDecisions();
    updateDecisionsSubtitle(decisions);
    updateFilterButtons();
    return status;
  } catch (e) {
    document.getElementById('service-status').textContent = 'Hors ligne';
    document.getElementById('service-status').className = 'status-pill status-danger';
    document.getElementById('decisions-body').innerHTML = `
      <tr><td colspan="9" class="empty-state">
        Impossible de joindre le service.<br>
        Démarrez-le : <code>bash scripts/10-start-web-ui.sh</code>
      </td></tr>`;
    return null;
  }
}

function startPolling(pamLive) {
  if (pollTimer) clearInterval(pollTimer);
  // Live PAM: ~0.5s refresh so Décisions tracks commands quickly.
  const interval = pamLive ? 500 : 15000;
  pollTimer = setInterval(refresh, interval);
}

document.addEventListener('DOMContentLoaded', async () => {
  if (!Auth.requireAuth('/login.html')) return;

  Auth.me().then((user) => {
    if (user && typeof fillUserChip === 'function') fillUserChip(user);
  });

  document.getElementById('btn-logout')?.addEventListener('click', (e) => {
    e.preventDefault();
    Auth.logout();
  });

  document.getElementById('btn-stop-pam')?.addEventListener('click', async () => {
    if (!await confirmAction('Arrêter la surveillance temps réel ?', 'Arrêter')) return;
    try {
      await Auth.api('/api/integration/stop', { method: 'POST', body: '{}' });
      await refresh();
      startPolling(false);
    } catch (err) {
      showToast('Erreur : ' + err.message, 'error');
    }
  });

  document.getElementById('btn-filter-all')?.addEventListener('click', async () => {
    alertsOnly = false;
    await refresh();
  });

  document.getElementById('btn-filter-alerts')?.addEventListener('click', async () => {
    alertsOnly = true;
    await refresh();
  });

  document.getElementById('btn-load-more')?.addEventListener('click', async () => {
    displayLimit = displayLimit < 100 ? 100 : 500;
    await refresh();
  });

  document.getElementById('btn-export-csv')?.addEventListener('click', () => {
    const data = filteredDecisions();
    if (!data.length) {
      showToast('Aucune donnée à exporter.');
      return;
    }
    const date = new Date().toISOString().slice(0, 10);
    exportDecisionsCsv(data, `cybervault-decisions-${date}.csv`);
  });

  document.getElementById('btn-clear-history')?.addEventListener('click', async () => {
    const total = document.getElementById('stat-total')?.textContent || '0';
    if (!await confirmAction(
      `Supprimer tout l'historique (${total} analyses) ? Cette action est irréversible.`,
      'Supprimer',
    )) return;
    try {
      const result = await Auth.api('/api/decisions/clear', { method: 'POST', body: '{}' });
      displayLimit = 30;
      alertsOnly = false;
      searchQuery = '';
      document.getElementById('search-input').value = '';
      await refresh();
      showToast(`${result.removed || 0} analyse(s) supprimée(s).`, 'success');
    } catch (err) {
      showToast('Erreur : ' + err.message, 'error');
    }
  });

  document.getElementById('search-input')?.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim();
    renderDecisions();
    updateDecisionsSubtitle({ stats: { total: document.getElementById('stat-total')?.textContent } });
  });

  document.getElementById('detail-close')?.addEventListener('click', closeDetail);
  document.getElementById('detail-backdrop')?.addEventListener('click', closeDetail);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDetail();
    if (e.key === 'Tab' && !document.getElementById('detail-modal')?.classList.contains('hidden')) {
      const panel = document.querySelector('#detail-modal .modal-panel');
      const focusable = [...panel.querySelectorAll('button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])')];
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  const status = await refresh();
  startPolling(status?.pam_live_active);
  document.getElementById('btn-refresh').addEventListener('click', refresh);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    } else if (!document.hidden) {
      refresh().then((current) => startPolling(current?.pam_live_active));
    }
  });
});
