/* Audit Assurance — shared utilities
 * State preservation: audit/control/filter/date in query params.
 * UI never computes compliance verdicts — renders API responses only.
 */
const AS = (() => {
  const params = new URLSearchParams(location.search);

  // 현재 컨텍스트 파라미터를 보존하며 URL 생성 (경로 내 기존 쿼리 병합)
  function url(path, extra = {}) {
    const u = new URL(String(path), location.origin);
    const p = u.searchParams;
    for (const k of ['audit', 'control', 'date', 'state', 'status', 'severity']) {
      if (extra[k] !== undefined) {
        if (extra[k] !== null && extra[k] !== '') p.set(k, extra[k]);
      } else if (!p.has(k)) {
        const v = params.get(k);
        if (v) p.set(k, v);
      }
    }
    for (const [k, v] of Object.entries(extra)) {
      if (['audit','control','date','state','status','severity'].includes(k)) continue;
      if (v !== null && v !== undefined && v !== '') p.set(k, v);
    }
    const q = p.toString();
    return u.pathname + (q ? `?${q}` : '');
  }

  function go(path, extra = {}) { location.href = url(path, extra); }
  async function api(path, opts = {}) {
    const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts });
    if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
    return res.json();
  }
  function get(k) { return params.get(k); }

  // 상태 → CSS 클래스/한글 라벨 매핑 (표시 전용)
  const STATE_LABEL = {
    READY: '준비완료', PARTIAL: '일부충족', MISSING: '미충족', CONFLICT: '불일치',
  };
  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // 심사 선택/유형 변경 → 컨텍스트 유지 이동
  function bindTopbar() {
    const sel = document.getElementById('auditSelector');
    if (sel) sel.addEventListener('change', () => go(location.pathname, { audit: sel.value }));
    const typeSel = document.getElementById('auditTypeSelect');
    if (typeSel) typeSel.addEventListener('change', () => {
      const map = { '최초심사': 'AUDIT-2024-INIT', '사후심사': 'AUDIT-2025-SURV', '갱신심사': 'AUDIT-DEMO-001' };
      go(location.pathname, { audit: map[typeSel.value] || 'AUDIT-DEMO-001' });
    });
    const tm = document.getElementById('timeMachineBtn');
    if (tm) tm.addEventListener('click', () => {
      const panel = document.getElementById('timeMachinePanel');
      if (panel) panel.classList.toggle('open');
      else go('/audit', { timemachine: '1' });
    });
  }

  // data-go 위임 — 템플릿 인라인 onclick 제거 (JS 컨텍스트 인젝션 방지)
  function bindDataGo() {
    const activate = el => go(el.dataset.go, el.dataset.goAudit !== undefined
      ? { audit: el.dataset.goAudit } : {});
    document.addEventListener('click', e => {
      const t = e.target.closest('[data-go]');
      if (t) activate(t);
    });
    document.addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      const t = e.target.closest('[data-go]');
      if (t) activate(t);
    });
  }

  document.addEventListener('DOMContentLoaded', bindDataGo);

  // 활동 스트림 폴링 (demo feed)
  function startActivity(el, intervalMs = 15000) {
    if (!el) return;
    async function tick() {
      try {
        const data = await api('/api/audit/activity');
        el.innerHTML = data.events.map(e => `
          <div class="stream-item">
            <span class="t">${esc(e.time)}</span>
            <span class="k k-${esc(e.kind)}"></span>
            <span><strong>${esc(e.control_id)}</strong> ${esc(e.text)}</span>
          </div>`).join('');
      } catch (_) { /* 네트워크 오류 시 조용히 유지 */ }
    }
    tick();
    return setInterval(tick, intervalMs);
  }

  document.addEventListener('DOMContentLoaded', bindTopbar);
  return { url, go, api, get, esc, STATE_LABEL, startActivity };
})();
