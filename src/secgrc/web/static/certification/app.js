/* Audit Assurance — shared utilities
 * State preservation: audit/control/filter/date in query params.
 * UI never computes compliance verdicts — renders API responses only.
 */
const AS = (() => {
  // 호출 시점의 현재 쿼리 — replaceState로 갱신된 date/audit도 반영
  const cur = () => new URLSearchParams(location.search);

  // 현재 컨텍스트 파라미터를 보존하며 URL 생성 (경로 내 기존 쿼리 병합)
  function url(path, extra = {}) {
    const u = new URL(String(path), location.origin);
    const p = u.searchParams;
    const now = cur();
    for (const k of ['audit', 'control', 'date', 'state', 'status', 'severity']) {
      if (extra[k] !== undefined) {
        if (extra[k] !== null && extra[k] !== '') p.set(k, extra[k]);
        else p.delete(k);
      } else if (!p.has(k)) {
        const v = now.get(k);
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
  function get(k) { return cur().get(k); }

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
      if (e.target.closest('a[href],[data-preview],[data-gapreg],[data-review]')) return;
      const t = e.target.closest('[data-go]');
      if (t) activate(t);
    });
    document.addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      if (e.target.closest('a[href],[data-preview],[data-gapreg],[data-review]')) return;
      const t = e.target.closest('[data-go]');
      if (t) activate(t);
    });
  }

  // 사이드바·브레드크럼 링크에 심사/타임머신 컨텍스트(audit,date) 유지
  // href도 미리 재작성해 새 탭 열기·링크 복사에서도 컨텍스트가 유지되게 함
  function preserveNavContext() {
    const SEL = '.sidebar a.nav-item[href], .crumb a[href^="/"], a.more[href^="/"]';
    const withCtx = href => url(href, {
      // 클릭 시점의 최신 컨텍스트로 덮어씀 (타임머신이 date를 갱신한 경우 반영)
      audit: cur().get('audit'), date: cur().get('date'),
      control: null, state: null, status: null, severity: null,
    });
    document.querySelectorAll(SEL).forEach(a => { a.href = withCtx(a.getAttribute('href')); });
    document.addEventListener('click', e => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const a = e.target.closest(SEL);
      if (!a) return;
      e.preventDefault();
      location.href = withCtx(a.getAttribute('href'));
    });
  }

  document.addEventListener('DOMContentLoaded', bindDataGo);
  document.addEventListener('DOMContentLoaded', preserveNavContext);

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

  // 증적 원문 인라인 미리보기 — 전역 모달 (base.html의 #evPreviewModal 사용)
  function previewModal() {
    return {
      root: document.getElementById('evPreviewModal'),
      title: document.getElementById('evPreviewTitle'),
      meta: document.getElementById('evPreviewMeta'),
      body: document.getElementById('evPreviewBody'),
    };
  }
  function closePreview() {
    const m = previewModal();
    if (m.root) m.root.hidden = true;
  }
  async function previewEvidence(id) {
    const m = previewModal();
    if (!m.root) return;
    m.root.hidden = false;
    m.title.textContent = id;
    m.meta.innerHTML = '';
    m.body.textContent = '불러오는 중…';
    try {
      const d = await api(`/api/audit/evidence/${encodeURIComponent(id)}/preview`);
      m.title.textContent = d.title || d.file_name || id;
      const chips = [];
      if (d.control_id) chips.push(`통제 ${d.control_id}`);
      if (d.doc_type) chips.push(d.doc_type);
      if (d.size != null) chips.push(`${(d.size / 1024).toFixed(1)} KB`);
      if (d.sha256) chips.push(`SHA-256 ${d.sha256.slice(0, 16)}…`);
      if (d.uploaded_at) chips.push(d.uploaded_at);
      m.meta.innerHTML = chips.map(c => `<span class="ev-chip">${esc(c)}</span>`).join('');
      if (d.kind === 'binary') {
        m.body.textContent = d.content ||
          '이 형식은 인라인 미리보기를 지원하지 않습니다. 증적 관리에서 원장 기록(해시·메타데이터)으로 무결성을 확인하세요.';
      } else {
        m.body.textContent = d.content || '표시할 내용이 없습니다.';
      }
    } catch (_) {
      m.title.textContent = id;
      m.meta.innerHTML = '';
      m.body.textContent = '원문을 불러오지 못했습니다.\n\n업로드된 파일이 없는 데모 증적이거나, 서버 재시작으로 업로드 이력과의 연결이 끊어졌습니다.\n파일 자체는 보존되어 있으므로 동일 파일을 다시 업로드하면 복구됩니다.';
    }
  }
  function bindPreview() {
    const m = previewModal();
    if (!m.root) return;
    document.addEventListener('click', e => {
      const b = e.target.closest('[data-preview]');
      if (!b) return;
      e.preventDefault();
      previewEvidence(b.dataset.preview);
    });
    const close = document.getElementById('evPreviewClose');
    if (close) close.addEventListener('click', closePreview);
    m.root.addEventListener('click', e => { if (e.target === m.root) closePreview(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closePreview(); });
  }
  document.addEventListener('DOMContentLoaded', bindPreview);

  // 리포트 생성 — 서버가 실제 데이터로 렌더링한 결과를 새 탭/다운로드로 제공
  function report(key) {
    window.open(url(`/reports/${encodeURIComponent(key)}`), '_blank');
  }

  document.addEventListener('DOMContentLoaded', bindTopbar);
  return { url, go, api, get, esc, STATE_LABEL, startActivity, previewEvidence, report };
})();
