"""Risk Engine — classifies findings and computes an overall risk score (0–100)."""


SEVERITY_WEIGHTS = {
    'critical': 25,
    'high': 12,
    'medium': 5,
    'low': 2,
    'info': 0,
}

SEVERITY_CAPS = {
    'critical': 50,  # max total deduction from critical findings
    'high': 30,
    'medium': 20,
    'low': 10,
    'info': 0,
}

RISK_LABELS = [
    (90, 'Excellent', '#00ff9f'),
    (75, 'Good', '#7fff00'),
    (55, 'Fair', '#ffb800'),
    (35, 'Poor', '#ff7700'),
    (0,  'Critical', '#ff2d55'),
]


def compute_risk_score(findings):
    """
    Given a list of finding dicts (each with a 'severity' key),
    compute a risk score from 0-100 and a breakdown dict.

    Returns (score: int, breakdown: dict)
    """
    breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

    for f in findings:
        sev = f.get('severity', 'info').lower()
        if sev in breakdown:
            breakdown[sev] += 1

    score = 100
    for sev, count in breakdown.items():
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        cap = SEVERITY_CAPS.get(sev, 0)
        deduction = min(count * weight, cap)
        score -= deduction

    score = max(0, min(100, score))
    return int(score), breakdown


def get_risk_label(score):
    for threshold, label, color in RISK_LABELS:
        if score >= threshold:
            return label, color
    return 'Critical', '#ff2d55'
