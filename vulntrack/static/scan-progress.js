'use strict';
document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('scan-progress');
  if (!root) return;
  let timer;
  const poll = async () => {
    try {
      const response = await fetch(root.dataset.statusUrl, {headers:{Accept:'application/json'},cache:'no-store'});
      if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Status unavailable');
      const data = await response.json();
      document.getElementById('scan-reconnect').hidden = true;
      document.getElementById('scan-status').textContent = data.status === 'completed' ? 'Your findings are ready' : data.status.charAt(0).toUpperCase() + data.status.slice(1);
      document.getElementById('scan-stage').textContent = data.status === 'completed' ? 'Analysis completed. Review the evidence and prioritize the issues.' : data.stage || (data.status === 'queued' ? 'Waiting for the background worker.' : 'Analyzing the approved target.');
      document.getElementById('scan-error').textContent = data.error || '';
      document.getElementById('scan-findings-count').textContent = String(data.findings_count);
      document.getElementById('scan-review').hidden = data.status !== 'completed';
      document.getElementById('scan-retry').hidden = !['failed','cancelled'].includes(data.status);
      document.getElementById('scan-cancel').hidden = !['queued','running'].includes(data.status) || data.cancel_requested;
      if (!['queued','running'].includes(data.status)) return;
    } catch (error) {
      document.getElementById('scan-reconnect').hidden = false;
    }
    timer = setTimeout(poll, 2500);
  };
  poll();
  window.addEventListener('pagehide', () => clearTimeout(timer));
});
