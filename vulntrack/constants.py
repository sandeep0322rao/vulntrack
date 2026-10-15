SEVERITIES = {'Critical': 100, 'High': 80, 'Medium': 55, 'Low': 30, 'Informational': 10}
STATUSES = {
    'open': 'Open', 'in_progress': 'In progress', 'ready_retest': 'Ready for retest',
    'remediated': 'Remediated', 'accepted_risk': 'Accepted risk', 'false_positive': 'False positive',
}
OPEN_STATUSES = ('open', 'in_progress', 'ready_retest', 'accepted_risk')
CATEGORIES = {
    'Unmapped': 'Needs classification',
    'A01:2025': 'Broken Access Control', 'A02:2025': 'Security Misconfiguration',
    'A03:2025': 'Software Supply Chain Failures', 'A04:2025': 'Cryptographic Failures',
    'A05:2025': 'Injection', 'A06:2025': 'Insecure Design',
    'A07:2025': 'Authentication Failures', 'A08:2025': 'Software or Data Integrity Failures',
    'A09:2025': 'Security Logging and Alerting Failures', 'A10:2025': 'Mishandling of Exceptional Conditions',
}
