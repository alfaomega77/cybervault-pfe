"""CyberVault Ava — product FAQ + general LLM (tech/math) + safe calculator."""

from __future__ import annotations

import ast
import json
import logging
import math
import operator
import os
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib import error, request

logger = logging.getLogger(__name__)

_FALLBACK = (
    "Je réponds sur CyberVault : produit, code, pipeline IA/ML, UEBA, APIs. "
    "Essaie « Comment marche le pipeline IA ? », « C’est quoi EventProcessor ? », "
    "« Comment entraîner les modèles ML ? »."
)
_FALLBACK_DARIJA = (
    "Kanjaweb 3la CyberVault: produit, code, pipeline IA/ML, UEBA, APIs. "
    "Jarrab: « Kifash khddam pipeline IA ? », « Chnou howa EventProcessor ? », "
    "« Kifash ntraini modèles ? »."
)

_DARIJA_HINTS = re.compile(
    r'('
    r'chnou|chno|achno|ashno|kifach|kifash|wash|wach|bghit|bghiti|n9der|nqder|'
    r'khddam|khddama|khdem|khdemto|khdemti|jarrab|jarreb|nssift|kayssift|nconnecti|imail|khatar|'
    r'3lach|3la|fhamni|chrh|chrah|salam|labas|bzaf|mzyan|7tal|7ott|t9der|'
    r'شنو|أشنو|كيفاش|واش|بغيت|شرح|سلام|خطر|إيميل'
    r')',
    re.IGNORECASE,
)

_MATH_TRIGGER = re.compile(
    r'(?i)('
    r'[\d\.]+\s*[\+\-\*/\^%]\s*[\d\.]+'
    r'|calcule|calculer|compute|solve|équation|equation|math'
    r'| deriv|intégr|integr|sqrt|log\(|sin\(|cos\(|tan\('
    r'|7seb|ahseb|حساب'
    r')'
)

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

_FUNCS = {
    'sqrt': math.sqrt,
    'sin': math.sin,
    'cos': math.cos,
    'tan': math.tan,
    'log': math.log,
    'log10': math.log10,
    'exp': math.exp,
    'abs': abs,
    'round': round,
    'floor': math.floor,
    'ceil': math.ceil,
}

_CONSTS = {'pi': math.pi, 'e': math.e}


def _normalize(text: str) -> str:
    text = unicodedata.normalize('NFD', (text or '').lower())
    text = ''.join(ch for ch in text if unicodedata.category(ch) != 'Mn')
    return text.translate(str.maketrans({'3': 'a', '7': 'h', '9': 'q', '8': 'g'})).strip()


def _variants(text: str) -> list[str]:
    raw = (text or '').lower().strip()
    nfd = unicodedata.normalize('NFD', raw)
    no_marks = ''.join(ch for ch in nfd if unicodedata.category(ch) != 'Mn')
    return list({raw, no_marks, _normalize(raw)})


def is_darija(message: str) -> bool:
    if re.search(r'[\u0600-\u06FF]', message or ''):
        return True
    return bool(_DARIJA_HINTS.search(message or ''))


@lru_cache(maxsize=1)
def load_knowledge() -> dict[str, Any]:
    candidates = [
        Path(__file__).resolve().parent / 'agent_knowledge.json',
        Path(__file__).resolve().parents[3] / 'frontend' / 'ai-agent' / 'knowledge.json',
        Path('/app/ai-agent/knowledge.json'),
    ]
    for path in candidates:
        if path.is_file():
            return json.loads(path.read_text(encoding='utf-8'))
    return {'agent': {}, 'entries': []}


def _score_entry(entry: dict[str, Any], query: str) -> int:
    variants = _variants(query)
    if not any(variants):
        return 0
    score = 0
    for kw in entry.get('keywords') or []:
        kw_vars = _variants(str(kw))
        hit = False
        for k in kw_vars:
            if len(k) < 2:
                continue
            for q in variants:
                matched = False
                if len(k) <= 3:
                    if re.search(rf'(?<![a-z0-9_]){re.escape(k)}(?![a-z0-9_])', q):
                        matched = True
                        score += 3
                elif k in q:
                    matched = True
                    # Prefer precise technical tokens (class/module names, long phrases)
                    if len(k) >= 12 or '_' in k:
                        score += 8
                    elif len(k) >= 8:
                        score += 5
                    else:
                        score += 4
                if matched:
                    hit = True
                    break
            if hit:
                break
        if not hit:
            parts = [p for p in _normalize(str(kw)).split() if len(p) > 2]
            if parts and all(any(p in q for q in variants) for p in parts):
                score += 2
    return score


def _pick_reply(entry: dict[str, Any], darija: bool) -> str:
    if darija and entry.get('answer_darija'):
        return entry['answer_darija']
    return entry.get('answer') or (_FALLBACK_DARIJA if darija else _FALLBACK)


def faq_match(message: str) -> tuple[dict[str, Any] | None, int]:
    entries = load_knowledge().get('entries') or []
    best = None
    best_score = 0
    for entry in entries:
        if entry.get('id') == 'fallback':
            continue
        score = _score_entry(entry, message)
        if score > best_score:
            best_score = score
            best = entry
    return best, best_score


def faq_answer(message: str) -> dict[str, Any]:
    darija = is_darija(message)
    best, best_score = faq_match(message)
    if best and best_score >= 2:
        return {
            'ok': True,
            'reply': _pick_reply(best, darija),
            'mode': 'faq',
            'matched_id': best.get('id'),
            'lang': 'darija' if darija else 'fr',
        }
    fallback = next((e for e in (load_knowledge().get('entries') or []) if e.get('id') == 'fallback'), {})
    return {
        'ok': True,
        'reply': _pick_reply(fallback, darija) if fallback else (_FALLBACK_DARIJA if darija else _FALLBACK),
        'mode': 'faq',
        'matched_id': 'fallback',
        'lang': 'darija' if darija else 'fr',
    }


def _eval_node(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.Name) and node.id in _CONSTS:
        return float(_CONSTS[node.id])
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return float(_OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right)))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return float(_OPS[type(node.op)](_eval_node(node.operand)))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        name = node.func.id
        if name not in _FUNCS or len(node.args) > 2 or node.keywords:
            raise ValueError('unsupported function')
        args = [_eval_node(a) for a in node.args]
        return float(_FUNCS[name](*args))
    raise ValueError('unsupported expression')


def try_math_answer(message: str) -> dict[str, Any] | None:
    """Safe calculator for basic arithmetic / functions (no LLM required)."""
    if not _MATH_TRIGGER.search(message or ''):
        return None
    darija = is_darija(message)
    # Extract the most likely expression
    expr = message
    for prefix in (
        r'(?i)calcule[rz]?\s*',
        r'(?i)compute\s*',
        r'(?i)solve\s*',
        r'(?i)7seb\s*',
        r'(?i)ahseb\s*',
        r'(?i)what is\s*',
        r'(?i)c[\'’]?est quoi\s*',
    ):
        expr = re.sub(prefix, '', expr).strip()
    expr = expr.replace('^', '**').replace('×', '*').replace('÷', '/')
    expr = re.sub(r'[^0-9a-zA-Z_\.\+\-\*/\(\)\s,%]', '', expr)
    expr = expr.strip().rstrip('=?؟')
    if not expr or len(expr) > 120:
        return None
    try:
        tree = ast.parse(expr, mode='eval')
        value = _eval_node(tree)
        if not math.isfinite(value):
            return None
        if abs(value - round(value)) < 1e-10:
            shown = str(int(round(value)))
        else:
            shown = f'{value:.10g}'
        if darija:
            reply = f'Natija: {shown}\n(Calcul local — pour les problèmes maths complexes, activez le LLM.)'
        else:
            reply = f'Résultat : {shown}\n(Calcul local — pour les problèmes maths avancés, activez le LLM.)'
        return {
            'ok': True,
            'reply': reply,
            'mode': 'math',
            'matched_id': 'calculator',
            'lang': 'darija' if darija else 'fr',
        }
    except Exception:
        return None


def llm_enabled() -> bool:
    key = os.getenv('AISS_AGENT_LLM_API_KEY', '').strip()
    url = os.getenv('AISS_AGENT_LLM_URL', '').strip().lower()
    # Ollama often uses a dummy key
    if key:
        return True
    return '11434' in url or 'ollama' in url


def _llm_answer(message: str) -> dict[str, Any] | None:
    if not llm_enabled():
        return None
    api_key = os.getenv('AISS_AGENT_LLM_API_KEY', '').strip() or 'ollama'
    url = os.getenv(
        'AISS_AGENT_LLM_URL',
        'https://api.openai.com/v1/chat/completions',
    ).strip()
    model = os.getenv('AISS_AGENT_LLM_MODEL', 'gpt-4o-mini').strip()
    kb = load_knowledge()
    corpus = '\n'.join(
        f"- {e.get('id')}: FR={e.get('answer')} | DAR={e.get('answer_darija') or e.get('answer')}"
        for e in (kb.get('entries') or [])
        if e.get('id') != 'fallback'
    )
    darija = is_darija(message)
    lang_rule = (
        'If the user writes Moroccan Darija, answer in Darija (latin chat script), clear and short. '
        'Otherwise answer in the user language (French or English).'
    )
    system = (
        'You are Ava, technical assistant for the CyberVault codebase '
        '(PAM Risk Intelligence on JumpServer). '
        'Prefer answering about THIS app: architecture, Python modules under backend/aiss/, '
        'EventProcessor pipeline, Rules/UEBA/ML/DL, MOO decisions, APIs, frontend, training. '
        'You may also help with related coding/ML/AI concepts when useful for understanding CyberVault. '
        'Be concrete (file paths, class names). Concise (max ~200 words). '
        'Never invent secrets or tokens. '
        f'{lang_rule}\n\n'
        'CyberVault technical corpus:\n'
        f'{corpus}'
    )
    payload = {
        'model': model,
        'temperature': 0.3,
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': message[:2000]},
        ],
    }
    req = request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
        },
        method='POST',
    )
    timeout = float(os.getenv('AISS_AGENT_LLM_TIMEOUT', '45'))
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode('utf-8'))
        reply = (
            ((body.get('choices') or [{}])[0].get('message') or {}).get('content') or ''
        ).strip()
        if not reply:
            return None
        return {
            'ok': True,
            'reply': reply,
            'mode': 'llm',
            'matched_id': None,
            'lang': 'darija' if darija else 'auto',
        }
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
        logger.warning('agent LLM failed: %s', exc)
        return None


def answer_agent_question(message: str) -> dict[str, Any]:
    text = re.sub(r'\s+', ' ', (message or '').strip())
    if not text:
        return {'ok': False, 'error': 'Message vide', 'reply': 'Kteb sou2al / Posez une question.'}
    if len(text) > 2000:
        return {'ok': False, 'error': 'Message trop long', 'reply': 'Message trop long (max 2000).'}

    # 1) Prefer LLM for open-ended / technical / math when configured
    if llm_enabled():
        # Strong product FAQ can still be answered instantly without token cost
        best, score = faq_match(text)
        productish = best is not None and score >= 6 and best.get('id') not in (None, 'fallback')
        wants_general = bool(
            _MATH_TRIGGER.search(text)
            or re.search(r'(?i)\b(python|java|docker|sql|algorithm|preuve|theorem|derive|integral)\b', text)
            or (best is None or score < 4)
        )
        if wants_general or not productish:
            llm = _llm_answer(text)
            if llm:
                return llm
        elif productish:
            return {
                'ok': True,
                'reply': _pick_reply(best, is_darija(text)),
                'mode': 'faq',
                'matched_id': best.get('id'),
                'lang': 'darija' if is_darija(text) else 'fr',
            }
            # if somehow empty, fall through

    # 2) Local math (works without LLM)
    math_hit = try_math_answer(text)
    if math_hit:
        return math_hit

    # 3) Product FAQ
    faq = faq_answer(text)
    if faq.get('matched_id') != 'fallback':
        return faq

    # 4) Honest capability message
    darija = is_darija(text)
    return {
        'ok': True,
        'reply': _FALLBACK_DARIJA if darija else _FALLBACK,
        'mode': 'need_llm',
        'matched_id': 'fallback',
        'lang': 'darija' if darija else 'fr',
        'llm_enabled': llm_enabled(),
    }


def agent_status() -> dict[str, Any]:
    return {
        'ok': True,
        'llm_enabled': llm_enabled(),
        'model': os.getenv('AISS_AGENT_LLM_MODEL', 'gpt-4o-mini') if llm_enabled() else None,
        'modes': ['faq', 'math', 'llm'] if llm_enabled() else ['faq', 'math'],
    }
