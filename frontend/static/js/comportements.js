/** Comportements anormaux — CRUD règles utilisateur */

const TYPE_LABELS = {
  command: 'Commande',
  unusual_hours: 'Heures',
  unusual_server: 'Serveur',
  unusual_ip: 'IP',
  custom: 'Personnalisé',
};

const TYPE_HINTS = {
  command: {
    label: 'Motif commande',
    placeholder: 'ex. rm\\s+-rf  ou  wget|curl',
    hint: 'Regex ou texte recherché dans la commande tapée.',
  },
  unusual_hours: {
    label: 'Heures interdites (UTC)',
    placeholder: 'ex. 22-6  ou  0,1,2,3,22,23',
    hint: 'Plage (22-6) ou liste d’heures 0–23. Toute activité à ces heures est signalée.',
  },
  unusual_server: {
    label: 'Serveur / asset',
    placeholder: 'ex. lab-db  ou  prod-payroll',
    hint: 'Nom ou ID du serveur. Toute commande sur cet asset est signalée.',
  },
  unusual_ip: {
    label: 'IP / CIDR',
    placeholder: 'ex. 203.0.113.10  ou  10.0.0.0/8',
    hint: 'IP exacte ou réseau CIDR source de la session.',
  },
  custom: {
    label: 'Regex personnalisée',
    placeholder: 'ex. (?i)base64\\s+-d',
    hint: 'Expression régulière appliquée à la commande.',
  },
};

function updatePatternHints() {
  const type = document.getElementById('rule_type')?.value || 'command';
  const meta = TYPE_HINTS[type] || TYPE_HINTS.command;
  const label = document.getElementById('rule_pattern_label');
  const input = document.getElementById('rule_pattern');
  const hint = document.getElementById('rule_pattern_hint');
  if (label) label.innerHTML = `${meta.label} <span style="color:var(--danger)">*</span>`;
  if (input) input.placeholder = meta.placeholder;
  if (hint) hint.textContent = meta.hint;
}

function setStatus(msg, isError) {
  const el = document.getElementById('rule-status');
  if (!el) return;
  el.textContent = msg || '';
  el.style.color = isError ? 'var(--danger)' : 'var(--muted)';
}

function renderRules(rules) {
  const list = document.getElementById('rules-list');
  const empty = document.getElementById('rules-empty');
  if (!list) return;
  list.innerHTML = '';
  if (!rules || !rules.length) {
    empty?.classList.remove('hidden');
    return;
  }
  empty?.classList.add('hidden');
  rules.forEach((rule) => {
    const card = document.createElement('div');
    card.className = 'rule-card' + (rule.enabled === false ? ' disabled' : '');
    card.innerHTML = `
      <div class="rule-head">
        <div>
          <span class="type-badge">${TYPE_LABELS[rule.type] || rule.type}</span>
          <h3 class="rule-title"></h3>
          <p class="rule-meta"></p>
        </div>
        <div class="rule-actions">
          <button type="button" class="btn-outline btn-toggle"></button>
          <button type="button" class="btn-outline btn-delete">Supprimer</button>
        </div>
      </div>
    `;
    card.querySelector('.rule-title').textContent = rule.name || 'Sans nom';
    const meta = [];
    meta.push(rule.pattern || '');
    meta.push(`risque ${Number(rule.risk_score ?? 0).toFixed(2)}`);
    if (rule.description) meta.push(rule.description);
    card.querySelector('.rule-meta').textContent = meta.filter(Boolean).join(' · ');
    const toggle = card.querySelector('.btn-toggle');
    toggle.textContent = rule.enabled === false ? 'Activer' : 'Désactiver';
    toggle.addEventListener('click', () => toggleRule(rule.id, rule.enabled === false));
    card.querySelector('.btn-delete').addEventListener('click', () => removeRule(rule.id));
    list.appendChild(card);
  });
}

async function loadRules() {
  const data = await Auth.api('/api/behavior-rules');
  renderRules(data.rules || []);
}

async function createRule(e) {
  e.preventDefault();
  setStatus('');
  const btn = document.getElementById('btn-save-rule');
  if (btn) btn.disabled = true;
  try {
    const body = {
      name: document.getElementById('rule_name').value.trim(),
      type: document.getElementById('rule_type').value,
      pattern: document.getElementById('rule_pattern').value.trim(),
      risk_score: parseFloat(document.getElementById('rule_risk').value || '0.85'),
      description: document.getElementById('rule_desc').value.trim(),
      enabled: true,
    };
    const data = await Auth.api('/api/behavior-rules', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    renderRules(data.rules || []);
    document.getElementById('rule-form').reset();
    document.getElementById('rule_risk').value = '0.85';
    updatePatternHints();
    setStatus('Règle ajoutée — active immédiatement.');
  } catch (err) {
    setStatus(err.message || 'Erreur', true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function toggleRule(id, enabled) {
  try {
    const data = await Auth.api('/api/behavior-rules/toggle', {
      method: 'POST',
      body: JSON.stringify({ id, enabled }),
    });
    renderRules(data.rules || []);
  } catch (err) {
    setStatus(err.message || 'Erreur', true);
  }
}

async function removeRule(id) {
  if (!confirm('Supprimer cette règle ?')) return;
  try {
    const data = await Auth.api('/api/behavior-rules/delete', {
      method: 'POST',
      body: JSON.stringify({ id }),
    });
    renderRules(data.rules || []);
    setStatus('Règle supprimée.');
  } catch (err) {
    setStatus(err.message || 'Erreur', true);
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  Auth.requireAuth();
  try {
    const me = await Auth.me();
    if (me && typeof fillUserChip === 'function') fillUserChip(me);
  } catch (_) { /* ignore */ }

  document.getElementById('rule_type')?.addEventListener('change', updatePatternHints);
  document.getElementById('rule-form')?.addEventListener('submit', createRule);
  updatePatternHints();

  try {
    await loadRules();
  } catch (err) {
    setStatus(err.message || 'Impossible de charger les règles', true);
  }

  if (typeof initAppShell === 'function') initAppShell();
  if (typeof initModeSwitch === 'function') initModeSwitch();
});
