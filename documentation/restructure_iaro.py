#!/usr/bin/env python3
"""Restructure Memoire_Final.tex to Master IARO PFE Guide outline."""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).with_name("Memoire_Final_pre_IARO_backup.tex")
DST = Path(__file__).with_name("Memoire_Final.tex")

SHORT_PILOTAGE = r"""
\section{Conduite du projet}
\label{sec:intro-pilotage}

Le projet a été conduit selon une approche Agile légère, de type Kanban,
adaptée à une preuve de concept exploratoire. Les travaux ont été organisés
par lots successifs (instrumentation JumpServer, moteurs de détection,
politique de réponse, interface et validation), avec un suivi simple de
l'avancement plutôt qu'un formalisme Scrum complet. Cette conduite a permis
d'ajuster rapidement les priorités lorsque des hypothèses techniques étaient
infirmées ou lorsque le schéma d'événements était mieux compris. Les détails
de backlog, de risques et de planification ne sont pas reproduits ici : le
mémoire privilégie la contribution scientifique et technique ; quelques
éléments complémentaires figurent en annexe
(Annexe~\ref{chap:app-management}).
"""

NEW_ORGANISATION = r"""
\section{Organisation du mémoire}
\label{sec:intro-outline}

Le mémoire suit la structure recommandée par le Guide PFE du Master IARO.
La présente introduction générale situe le contexte, la problématique, les
objectifs, la méthodologie et les contributions. Le
Chapitre~\ref{chap:sota} présente l'état de l'art sur la PAM, la détection
comportementale et l'optimisation de la réponse, puis identifie le gap
scientifique. Le Chapitre~\ref{chap:method} expose la méthodologie proposée :
conception de CyberVault, formalisation des détecteurs, explicabilité et
politique multiobjectif. Le Chapitre~\ref{chap:impl} décrit
l'implémentation, les données, le déploiement et le fonctionnement en temps
réel, ainsi que les protocoles expérimentaux. Le
Chapitre~\ref{chap:discussion} analyse et discute les résultats, les limites
et les perspectives. La conclusion générale synthétise les apports et ouvre
les travaux futurs. Les annexes rassemblent des éléments de reproductibilité,
de gestion et de configuration.
"""

INTRO_OPENING_NOTE = r"""
\chapter{Introduction générale}
\label{chap:intro}

"""


def split_chapters(text: str) -> list[tuple[str, str]]:
    """Return list of (header_line, body_including_header)."""
    parts = re.split(r'(?=^\\chapter\*\{|^\\chapter\{)', text, flags=re.M)
    preamble = parts[0]
    chapters = []
    for part in parts[1:]:
        first = part.split("\n", 1)[0]
        chapters.append((first, part))
    return preamble, chapters


def chapter_title(header: str) -> str:
    m = re.search(r'\\chapter\*?\{([^}]+)\}', header)
    return m.group(1) if m else header


def replace_label(body: str, old: str, new: str) -> str:
    return body.replace(f"\\label{{{old}}}", f"\\label{{{new}}}")


def strip_sections(body: str, section_titles: list[str]) -> str:
    """Remove named \\section{...} blocks until next \\section/\\chapter."""
    for title in section_titles:
        pat = re.compile(
            rf'^\\section\{{{re.escape(title)}\}}.*?(?=^\\section\{{|^\\chapter\{{|\Z)',
            re.M | re.S,
        )
        body = pat.sub("", body, count=1)
    return body


def main() -> None:
    text = SRC.read_text(encoding="utf-8")
    preamble, chapters = split_chapters(text)

    by_title = {chapter_title(h): body for h, body in chapters}

    # --- Introduction: rename + drop Limites générales + replace organisation + insert pilotage ---
    intro = by_title["Contexte, stage et problématique"]
    intro = intro.replace(
        "\\chapter{Contexte, stage et problématique}",
        "\\chapter{Introduction générale}",
        1,
    )
    intro = strip_sections(intro, ["Limites générales", "Organisation du mémoire"])
    # insert short pilotage + new organisation before end of intro chapter
    # remove trailing transition that points to management chapter
    intro = re.sub(
        r"Avant ces développements.*?projet qui a rendu cette démarche possible\.\s*",
        "",
        intro,
        flags=re.S,
    )
    intro = intro.rstrip() + "\n" + SHORT_PILOTAGE + "\n" + NEW_ORGANISATION + "\n"

    # --- Drop full pilotage from main flow; keep thin annex later ---
    pilotage_full = by_title["Pilotage du projet"]

    # --- Chapter 1: État de l'art ---
    sota = by_title["PAM et état de l'art"]
    sota = sota.replace(
        "\\chapter{PAM et état de l'art}",
        "\\chapter{État de l'art}",
        1,
    )
    sota = replace_label(sota, "chap:domain", "chap:sota")
    # strengthen gap section title if needed
    sota = sota.replace(
        "\\section{Lacune scientifique et positionnement}",
        "\\section{Gap scientifique et positionnement de CyberVault}",
        1,
    )
    sota = sota.replace(
        "\\section{Synthèse et transition vers la conception}",
        "\\section{Synthèse et transition}",
        1,
    )
    # soft rewrite closing transition
    sota = re.sub(
        r"Cette synthèse prépare.*?conception\.\s*",
        "Cette synthèse prépare la méthodologie proposée au chapitre suivant.\n\n",
        sota,
        count=1,
        flags=re.S,
    )

    # --- Chapter 2: Méthodologie = Conception + IA/RO ---
    conception = by_title["Conception de CyberVault"]
    conception = conception.replace(
        "\\chapter{Conception de CyberVault}",
        "\\chapter{Méthodologie proposée}\n\\label{chap:method}\n\n"
        "\\section{Conception architecturale de CyberVault}",
        1,
    )
    # remove old chapter label line if present as separate
    conception = conception.replace("\\label{chap:architecture}\n", "", 1)
    # demote former top-level sections under conception stay as \section
    # Change closing transition
    conception = conception.replace(
        "\\section{Synthèse et transition vers l'IA et la recherche opérationnelle}",
        "\\section{Synthèse de la conception et transition vers les modèles}",
        1,
    )

    ai = by_title["Intelligence artificielle et recherche opérationnelle"]
    ai = ai.replace(
        "\\chapter{Intelligence artificielle et recherche opérationnelle}",
        "\\section{Intelligence artificielle et recherche opérationnelle}",
        1,
    )
    ai = ai.replace("\\label{chap:ai-ro}\n", "\\label{sec:method-ai-ro}\n", 1)
    # demote former \section to \subsection and \subsection to \subsubsection in AI block
    # Careful: only for the AI chapter body. Do stepwise.
    ai_lines = ai.splitlines(keepends=True)
    out_ai = []
    for line in ai_lines:
        if line.startswith("\\section{"):
            line = "\\subsection{" + line[len("\\section{") :]
        elif line.startswith("\\subsection{"):
            line = "\\subsubsection{" + line[len("\\subsection{") :]
        out_ai.append(line)
    ai = "".join(out_ai)
    ai = ai.replace(
        "\\subsection{Transition vers les données et l'apprentissage}",
        "\\subsection{Synthèse méthodologique et transition}",
        1,
    )
    method = conception.rstrip() + "\n\n" + ai + "\n"

    # --- Chapter 3: Implémentation et expérimentation ---
    data = by_title["Données et apprentissage"]
    data = data.replace(
        "\\chapter{Données et apprentissage}",
        "\\chapter{Implémentation et expérimentation}\n\\label{chap:impl}\n\n"
        "\\section{Données et apprentissage}",
        1,
    )
    data = data.replace("\\label{chap:data}\n", "", 1)

    deploy = by_title["Implémentation et déploiement"]
    deploy = deploy.replace(
        "\\chapter{Implémentation et déploiement}",
        "\\section{Implémentation et déploiement}",
        1,
    )
    deploy = deploy.replace("\\label{chap:deployment}\n", "\\label{sec:impl-deploy}\n", 1)

    realtime = by_title["Fonctionnement en temps réel"]
    realtime = realtime.replace(
        "\\chapter{Fonctionnement en temps réel}",
        "\\section{Fonctionnement en temps réel}",
        1,
    )
    realtime = realtime.replace("\\label{chap:realtime}\n", "\\label{sec:impl-realtime}\n", 1)

    validation = by_title["Validation transversale et discussion"]
    # Extract experimental/results sections for Ch3, keep discussion for Ch4
    # Split validation into results vs discussion
    val_body = validation
    # Take from start through "Politique à seuils..." and "Analyse des erreurs" and "Reproductibilité" as results-ish
    # Discussion chapter gets: Objet, Comparaison (keep both?), Menaces, Réponses QR, Implications, Éthique, Feuille de route, Synthèse

    # For Ch3 add a section with experimental results extracted from validation
    # We'll put comparison/detection results section into Ch3
    m_obj = re.search(
        r'^\\section\{Objet de la validation.*?(?=^\\section\{)',
        val_body,
        re.M | re.S,
    )
    m_comp = re.search(
        r'^\\section\{Comparaison transversale des compromis de détection\}.*?(?=^\\section\{Politique)',
        val_body,
        re.M | re.S,
    )
    m_pol = re.search(
        r'^\\section\{Politique à seuils.*?(?=^\\section\{Analyse des erreurs)',
        val_body,
        re.M | re.S,
    )
    m_err = re.search(
        r'^\\section\{Analyse des erreurs.*?(?=^\\section\{Reproductibilité)',
        val_body,
        re.M | re.S,
    )
    m_repro = re.search(
        r'^\\section\{Reproductibilité et audit des artefacts\}.*?(?=^\\section\{Menaces)',
        val_body,
        re.M | re.S,
    )

    results_parts = ["\\section{Résultats expérimentaux principaux}\n"]
    if m_obj:
        # shorten: keep as subsection
        block = m_obj.group(0)
        block = block.replace("\\section{", "\\subsection{", 1)
        results_parts.append(block)
    if m_comp:
        block = m_comp.group(0).replace("\\section{", "\\subsection{", 1)
        results_parts.append(block)
    if m_pol:
        block = m_pol.group(0).replace("\\section{", "\\subsection{", 1)
        results_parts.append(block)
    if m_err:
        block = m_err.group(0).replace("\\section{", "\\subsection{", 1)
        results_parts.append(block)
    if m_repro:
        block = m_repro.group(0).replace("\\section{", "\\subsection{", 1)
        results_parts.append(block)
    results_section = "\n".join(results_parts) + "\n"

    impl = (
        data.rstrip()
        + "\n\n"
        + deploy
        + "\n\n"
        + realtime
        + "\n\n"
        + results_section
        + "\n"
    )
    # Demote former chapter-level sections inside data/deploy/realtime that were \section
    # already OK (data became section under ch3)

    # Demote nested sections in deploy and realtime that conflict? Keep as is.

    # --- Chapter 4: Analyse et discussion ---
    m_threat = re.search(
        r'^\\section\{Menaces à la validité\}.*?(?=^\\section\{Réponses)',
        val_body,
        re.M | re.S,
    )
    m_qr = re.search(
        r'^\\section\{Réponses aux questions de recherche\}.*?(?=^\\section\{Implications)',
        val_body,
        re.M | re.S,
    )
    m_ind = re.search(
        r'^\\section\{Implications industrielles.*?(?=^\\section\{Éthique)',
        val_body,
        re.M | re.S,
    )
    m_eth = re.search(
        r'^\\section\{Éthique, responsabilité et sûreté\}.*?(?=^\\section\{Déploiement progressif)',
        val_body,
        re.M | re.S,
    )
    m_road = re.search(
        r'^\\section\{Déploiement progressif.*?(?=^\\section\{Synthèse et transition\}|^\\chapter\{|\Z)',
        val_body,
        re.M | re.S,
    )
    m_syn = re.search(
        r'^\\section\{Synthèse et transition\}.*?(?=^\\chapter\{|\Z)',
        val_body,
        re.M | re.S,
    )

    discussion_parts = [
        "\\chapter{Analyse et discussion}\n\\label{chap:discussion}\n\n",
        "Ce chapitre interprète les résultats expérimentaux, les compare à l'état "
        "de l'art, discute les limites et les menaces sur la validité, puis précise "
        "les perspectives. Les mesures détaillées ont été présentées au "
        "Chapitre~\\ref{chap:impl} ; l'accent est placé ici sur la lecture "
        "scientifique et industrielle.\n\n",
    ]
    for m in (m_threat, m_qr, m_ind, m_eth, m_road):
        if m:
            discussion_parts.append(m.group(0) + "\n")
    if m_syn:
        block = m_syn.group(0).replace(
            "\\section{Synthèse et transition}",
            "\\section{Synthèse de la discussion}",
            1,
        )
        discussion_parts.append(block + "\n")
    discussion = "".join(discussion_parts)

    # --- Conclusion ---
    conclusion = by_title["Conclusion générale"]

    # --- Annexes ---
    annex_management = (
        "\\chapter{Annexe : éléments de pilotage}\n"
        "\\label{chap:app-management}\n\n"
        "Cette annexe rappelle brièvement que le projet a été suivi avec une "
        "approche Agile/Kanban adaptée à un POC. Les registres détaillés de "
        "backlog, user stories et risques ont servi à l'organisation du stage, "
        "mais ne constituent pas le cœur scientifique du mémoire. Les figures "
        "de planification éventuellement conservées dans le dépôt documentaire "
        "peuvent être consultées séparément si nécessaire.\n\n"
    )
    # Keep a very short extract from original pilotage intro only
    m_pilot_intro = re.search(
        r'^\\section\{Une conduite adaptée.*?(?=^\\section\{)',
        pilotage_full,
        re.M | re.S,
    )
    if m_pilot_intro:
        block = m_pilot_intro.group(0)
        # truncate to ~2500 chars
        if len(block) > 2500:
            block = block[:2500].rsplit(".", 1)[0] + ".\n\n"
        annex_management += block.replace("\\section{", "\\section{", 1)

    annexes = []
    for title in [
        "Dossier de reproductibilité",
        "Périmètre de l'état d'implémentation",
        "Éthique et IA responsable",
        "Notes sur l'API, les événements et la configuration",
    ]:
        if title in by_title:
            body = by_title[title]
            # rename to Annexe if not already
            body = re.sub(
                r"^\\chapter\{",
                r"\\chapter{Annexe : ",
                body,
                count=1,
                flags=re.M,
            )
            # avoid double Annexe
            body = body.replace("Annexe : Annexe : ", "Annexe : ", 1)
            annexes.append(body)

    # Drop old "Éléments probants de gestion de projet" heavy annex; replaced
    # Keep starred front matter chapters
    front = []
    for h, body in chapters:
        t = chapter_title(h)
        if t in {
            "Déclaration",
            "Remerciements",
            "Abstract",
            "Résumé",
            "Liste des abréviations",
        }:
            front.append(body)

    # Fix common cross-refs in whole assembled text later
    assembled = (
        preamble
        + "".join(front)
        + intro
        + sota
        + method
        + impl
        + discussion
        + conclusion
        + annex_management
        + "".join(annexes)
    )

    # Bibliography and anything after conclusion was inside conclusion chapter in original?
    # Check: conclusion chapter may end before bib; bib was AFTER conclusion in original
    # In original split, Conclusion included text until next chapter "Dossier..."
    # Bibliography is AFTER all chapters - need to check if bib is in preamble remainder

    # Find bibliography in original text after last chapter
    bib_match = re.search(r'\\begin\{thebibliography\}.*\\end\{thebibliography\}', text, re.S)
    if bib_match and "\\begin{thebibliography}" not in assembled:
        assembled += "\n" + bib_match.group(0) + "\n\\end{document}\n"
    elif not assembled.rstrip().endswith("\\end{document}"):
        if "\\end{document}" not in assembled:
            assembled += "\n\\end{document}\n"

    # Cross-reference remaps
    replacements = {
        "chap:domain": "chap:sota",
        "chap:architecture": "chap:method",
        "chap:ai-ro": "sec:method-ai-ro",
        "chap:data": "chap:impl",
        "chap:deployment": "sec:impl-deploy",
        "chap:realtime": "sec:impl-realtime",
        "chap:validation": "chap:discussion",
        "chap:management": "chap:app-management",
        "Chapitre~\\ref{chap:management}": "l'annexe~\\ref{chap:app-management}",
    }
    for old, new in replacements.items():
        assembled = assembled.replace(old, new)

    # Clean duplicate labels chap:method if any
    # Ensure listoffigures already in preamble area - already present

    # Light style: remove obvious "Le chapitre suivant" management transitions left
    assembled = assembled.replace(
        "le chapitre suivant présente le pilotage du projet qui a rendu cette démarche possible.",
        "les chapitres suivants développent l'état de l'art, la méthodologie, l'expérimentation et la discussion.",
    )

    DST.write_text(assembled, encoding="utf-8")
    print(f"Wrote {DST} ({len(assembled)} chars, {assembled.count(chr(10))} lines)")
    # report chapters
    for m in re.finditer(r'^\\chapter\*?\{([^}]+)\}', assembled, re.M):
        print(" -", m.group(1))


if __name__ == "__main__":
    main()
