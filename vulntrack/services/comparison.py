from collections import defaultdict

from ..constants import OPEN_STATUSES


def compare(baseline, retest):
    """Compare fingerprints without treating scanner absence as remediation."""
    before, after = defaultdict(list), defaultdict(list)
    for f in baseline.findings:
        before[f.fingerprint].append(f)
    for f in retest.findings:
        after[f.fingerprint].append(f)
    result = {'remediated': [], 'persisting': [], 'new': [], 'not_observed': []}
    for fp, findings in before.items():
        matches = after.get(fp, [])
        if not matches:
            result['not_observed'].extend(findings)
        elif all(f.status == 'remediated' and f.retested_at for f in matches):
            result['remediated'].extend(matches)
        else:
            result['persisting'].extend(matches)
    for fp in after.keys() - before.keys():
        result['new'].extend(after[fp])
    before_risk = round(sum(f.risk_score for f in baseline.findings if f.status in OPEN_STATUSES), 2)
    after_risk = round(sum(f.risk_score for f in retest.findings if f.status in OPEN_STATUSES), 2)
    result.update(before_risk=before_risk, after_risk=after_risk,
                  reduction=None if before_risk == 0 else round((before_risk - after_risk) / before_risk * 100, 1))
    return result
