/** CyberVault AI Agent — Sam-style floating assistant */

(function () {
  const ROOT_ID = 'cv-agent-root';
  const KNOWLEDGE_URL = '/ai-agent/knowledge.json';
  const API_URL = '/api/agent/chat';

  let knowledge = null;
  let open = false;
  let busy = false;

  function normalize(text) {
    return String(text || '')
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/3/g, 'a')
      .replace(/7/g, 'h')
      .replace(/9/g, 'q')
      .replace(/8/g, 'g')
      .trim();
  }

  function variants(text) {
    const raw = String(text || '').toLowerCase().trim();
    const noMarks = raw.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    return [...new Set([raw, noMarks, normalize(raw)])];
  }

  function isDarija(message) {
    if (/[\u0600-\u06FF]/.test(message || '')) return true;
    return /(chnou|chno|achno|ashno|kifach|kifash|wash|wach|bghit|bghiti|n9der|nqder|khddam|khdem|khdemto|khdemti|jarrab|jarreb|kayssift|nconnecti|imail|khatar|3lach|fhamni|chrh|chrah|salam|t9der|شنو|أشنو|كيفاش|واش|بغيت|شرح|سلام)/i.test(
      message || '',
    );
  }

  function scoreEntry(entry, query) {
    const qVars = variants(query);
    if (!qVars.some(Boolean)) return 0;
    let score = 0;
    for (const kw of entry.keywords || []) {
      const kwVars = variants(kw);
      let hit = false;
      for (const k of kwVars) {
        if (k.length < 2) continue;
        for (const q of qVars) {
          if (k.length <= 3) {
            const re = new RegExp(`(?<![a-z0-9])${k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![a-z0-9])`);
            if (re.test(q)) {
              score += 3;
              hit = true;
              break;
            }
          } else if (q.includes(k)) {
            score += k.length >= 5 ? 4 : 3;
            hit = true;
            break;
          }
        }
        if (hit) break;
      }
      if (!hit) {
        const parts = normalize(kw).split(/\s+/).filter((p) => p.length > 2);
        if (parts.length && parts.every((p) => qVars.some((q) => q.includes(p)))) {
          score += 2;
        }
      }
    }
    return score;
  }

  function pickReply(entry, darija) {
    if (darija && entry.answer_darija) return entry.answer_darija;
    return entry.answer || (darija
      ? 'Kanjaweb 3la CyberVault. Jarrab: « Chnou howa CyberVault? ».'
      : 'Posez une question sur CyberVault.');
  }

  function localAnswer(message) {
    const entries = knowledge?.entries || [];
    const darija = isDarija(message);
    let best = null;
    let bestScore = 0;
    for (const entry of entries) {
      if (entry.id === 'fallback') continue;
      const s = scoreEntry(entry, message);
      if (s > bestScore) {
        bestScore = s;
        best = entry;
      }
    }
    if (best && bestScore >= 2) {
      return { reply: pickReply(best, darija), mode: 'faq', matched_id: best.id, lang: darija ? 'darija' : 'fr' };
    }
    const fallback = entries.find((e) => e.id === 'fallback') || {};
    return {
      reply: pickReply(fallback, darija),
      mode: 'faq',
      matched_id: 'fallback',
      lang: darija ? 'darija' : 'fr',
    };
  }

  async function ask(message) {
    try {
      const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.reply) return data;
      }
    } catch (_) {
      /* fall back to local knowledge */
    }
    return localAnswer(message);
  }

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (key === 'className') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'html') node.innerHTML = value;
      else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
      else if (value !== undefined && value !== null) node.setAttribute(key, value);
    });
    children.forEach((child) => {
      if (child == null) return;
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }

  function appendMessage(list, role, text) {
    const bubble = el('div', { className: `cv-agent-msg ${role}`, text });
    list.appendChild(bubble);
    list.scrollTop = list.scrollHeight;
    return bubble;
  }

  function setOpen(next, refs) {
    open = next;
    refs.panel.hidden = !open;
    refs.fab.classList.toggle('is-open', open);
    refs.fab.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) {
      refs.input.focus();
    }
  }

  async function handleSend(refs, raw) {
    const message = String(raw || '').trim();
    if (!message || busy) return;
    busy = true;
    refs.send.disabled = true;
    refs.input.value = '';
    refs.suggestions.hidden = true;
    appendMessage(refs.messages, 'user', message);
    const typing = appendMessage(refs.messages, 'bot typing', 'Ava réfléchit…');
    try {
      const data = await ask(message);
      typing.remove();
      appendMessage(refs.messages, 'bot', data.reply);
    } catch (err) {
      typing.remove();
      appendMessage(refs.messages, 'bot', err.message || 'Une erreur est survenue.');
    } finally {
      busy = false;
      refs.send.disabled = false;
      refs.input.focus();
    }
  }

  function mount(meta) {
    if (document.getElementById(ROOT_ID)) return;

    const root = el('div', { id: ROOT_ID, className: 'cv-agent-root' });
    const fab = el('button', {
      type: 'button',
      className: 'cv-agent-fab',
      'aria-expanded': 'false',
      'aria-controls': 'cv-agent-panel',
      title: 'Ouvrir l’assistante CyberVault',
    }, [
      el('span', { className: 'cv-agent-fab-avatar', text: 'AV' }),
      el('span', { className: 'cv-agent-fab-label', text: 'Ask Ava' }),
    ]);

    const panel = el('aside', {
      id: 'cv-agent-panel',
      className: 'cv-agent-panel',
      role: 'dialog',
      'aria-label': meta.title || 'Assistante CyberVault',
      hidden: 'true',
    });

    const closeBtn = el('button', {
      type: 'button',
      className: 'cv-agent-close',
      'aria-label': 'Fermer',
      text: '×',
    });

    const header = el('div', { className: 'cv-agent-header' }, [
      el('div', { className: 'cv-agent-identity' }, [
        el('div', { className: 'cv-agent-avatar', text: 'AV' }),
        el('div', {}, [
          el('strong', { text: meta.name || 'Ava' }),
          el('span', { text: meta.title || 'Assistante CyberVault' }),
        ]),
      ]),
      closeBtn,
    ]);

    const hero = el('div', { className: 'cv-agent-hero' }, [
      el('div', { className: 'cv-agent-hero-card' }, [
        el('strong', { text: `${meta.name || 'Ava'} AI Representative` }),
        el('p', { text: 'Posez vos questions sur le fonctionnement de CyberVault — simulation, PAM, dry-run, alertes.' }),
      ]),
    ]);

    const messages = el('div', {
      className: 'cv-agent-messages',
      role: 'log',
      'aria-live': 'polite',
    });
    appendMessage(messages, 'bot', meta.greeting || 'Bonjour !');

    const suggestions = el('div', { className: 'cv-agent-suggestions' });
    (meta.suggestions || []).forEach((label) => {
      suggestions.appendChild(
        el('button', {
          type: 'button',
          className: 'cv-agent-chip',
          text: label,
          onClick: () => handleSend(refs, label),
        }),
      );
    });

    const input = el('input', {
      type: 'text',
      placeholder: 'Posez une question à Ava',
      autocomplete: 'off',
      maxlength: '2000',
      'aria-label': 'Votre question',
    });
    const send = el('button', {
      type: 'button',
      className: 'cv-agent-send',
      'aria-label': 'Envoyer',
      text: '→',
    });
    const composer = el('div', { className: 'cv-agent-composer' }, [input, send]);
    const legal = el('p', {
      className: 'cv-agent-legal',
      text: 'Ava : questions produit + code / ML / IA CyberVault (FR & darija).',
    });

    panel.append(header, hero, messages, suggestions, composer, legal);
    root.append(fab, panel);
    document.body.appendChild(root);

    const refs = { fab, panel, messages, suggestions, input, send };

    fab.addEventListener('click', () => setOpen(true, refs));
    closeBtn.addEventListener('click', () => setOpen(false, refs));
    send.addEventListener('click', () => handleSend(refs, input.value));
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        handleSend(refs, input.value);
      }
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && open) setOpen(false, refs);
    });
  }

  async function boot() {
    try {
      const res = await fetch(KNOWLEDGE_URL, { cache: 'no-store' });
      knowledge = res.ok ? await res.json() : { agent: {}, entries: [] };
    } catch (_) {
      knowledge = { agent: {}, entries: [] };
    }
    mount(knowledge.agent || {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
