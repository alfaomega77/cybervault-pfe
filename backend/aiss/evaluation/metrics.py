"""Evaluation metrics for anomaly detection benchmarks."""

from typing import Dict, List, Tuple


def confusion_matrix(y_true: List[int], y_pred: List[int]) -> Dict[str, int]:
    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred):
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn}


def classification_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    cm = confusion_matrix(y_true, y_pred)
    tp, fp, tn, fn = cm['tp'], cm['fp'], cm['tn'], cm['fn']
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        'accuracy': round(accuracy, 4),
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'false_positive_rate': round(fpr, 4),
        **cm,
    }


def disruption_cost(actions: List[str], y_true: List[int]) -> Dict[str, float]:
    disruptive = {'ALERT_ANALYST', 'CREATE_TICKET', 'LOCK_SESSION', 'KILL_SESSION'}
    total = len(y_true)
    false_disruptions = sum(
        1 for action, label in zip(actions, y_true)
        if label == 0 and action in disruptive
    )
    missed_threats = sum(
        1 for action, label in zip(actions, y_true)
        if label == 1 and action in ('NO_ACTION', 'LOG_ONLY')
    )
    return {
        'false_disruption_rate': round(false_disruptions / total, 4) if total else 0.0,
        'missed_threat_rate': round(missed_threats / total, 4) if total else 0.0,
    }


def markdown_table(headers: List[str], rows: List[List[str]]) -> str:
    lines = [
        '| ' + ' | '.join(headers) + ' |',
        '| ' + ' | '.join(['---'] * len(headers)) + ' |',
    ]
    for row in rows:
        lines.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
    return '\n'.join(lines)
