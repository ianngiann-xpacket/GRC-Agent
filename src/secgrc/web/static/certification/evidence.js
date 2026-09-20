/* Evidence Management — 검토·승인 패널 (담당자 → 팀장 → CISO)
 * 원장 REVIEW/ANNOTATION 레코드 기반. 모든 동적 값은 AS.esc()로 이스케이프.
 */
(() => {
  const modal = document.getElementById('reviewModal');
  if (!modal || typeof AS === 'undefined') return;
  const $ = id => document.getElementById(id);
  let curId = null;

  const STAGES = [
    ['TEAM_LEAD_REVIEW', '① 담당자 제출 → 팀장'],
    ['CISO_REVIEW', '② CISO 승인'],
    ['APPROVED', '③ 확정'],
  ];
  const ACTION_LABELS = { approve: '승인', reject: '반려', resubmit: '재제출' };
  const ACTION_COLORS = { approve: 'var(--green)', reject: 'var(--red)', resubmit: 'var(--blue)' };

  function showMsg(text, isErr) {
    const el = $('reviewMsg');
    el.style.display = 'block';
    el.style.color = isErr ? 'var(--red)' : 'var(--green)';
    el.textContent = text;
  }

  function listHtml(items, empty, rowFn) {
    if (!items.length) return `<div style="font-size:11.5px;color:var(--muted);padding:6px 0">${empty}</div>`;
    return items.map(rowFn).join('');
  }

  async function load() {
    const d = await AS.api(`/api/audit/evidence/${encodeURIComponent(curId)}/review`);
    $('reviewTitle').textContent = `${curId} — 검토·승인`;
    $('reviewStage').innerHTML =
      `<span class="badge" style="font-size:10.5px;background:${d.stage === 'APPROVED' ? 'var(--green-soft);color:var(--green)' : d.stage === 'REJECTED' ? 'var(--red-soft);color:var(--red)' : 'var(--amber-soft);color:var(--amber)'}">${AS.esc(d.stage_label)}</span>` +
      (d.next_actor ? ` <span style="color:var(--muted)">다음 처리: ${AS.esc(d.next_actor)}</span>` : '');

    // 진행 단계 칩
    const order = ['TEAM_LEAD_REVIEW', 'CISO_REVIEW', 'APPROVED'];
    const idx = d.stage === 'REJECTED' ? -1 : order.indexOf(d.stage);
    $('reviewSteps').innerHTML = STAGES.map(([k, label], i) => {
      const done = i < idx || d.stage === 'APPROVED';
      const cur = i === idx;
      return `<span style="flex:1;text-align:center;font-size:11px;padding:6px 4px;border-radius:8px;
        background:${done || cur ? 'var(--blue-soft,#eff6ff)' : '#f8fafc'};
        color:${done || cur ? 'var(--blue)' : 'var(--muted)'};
        font-weight:${cur ? '700' : '500'};border:1px solid ${cur ? 'var(--blue)' : '#e3e8f0'}">${label}</span>`;
    }).join('') + (d.stage === 'REJECTED' ? `<span style="flex:0.6;text-align:center;font-size:11px;padding:6px 4px;border-radius:8px;background:var(--red-soft);color:var(--red);font-weight:700;border:1px solid var(--red)">반려됨</span>` : '');

    // 결재 버튼 — 서버가 허용한 action만
    $('reviewBtns').innerHTML = (d.allowed_actions || []).map(a =>
      `<button type="button" class="tb-btn" data-act="${a}"
        style="font-size:11.5px;padding:5px 14px;color:#fff;background:${ACTION_COLORS[a]};border-color:${ACTION_COLORS[a]}">${ACTION_LABELS[a]}</button>`
    ).join('') || '<span style="font-size:11.5px;color:var(--muted)">이 단계에서 처리 가능한 결재가 없습니다.</span>';
    $('reviewBtns').querySelectorAll('button[data-act]').forEach(b =>
      b.addEventListener('click', () => submitTransition(b.dataset.act)));

    $('reviewComments').innerHTML = listHtml(d.comments || [], '등록된 코멘트 없음', c =>
      `<div style="font-size:11.5px;padding:7px 10px;background:#f8fafc;border-radius:8px;margin-bottom:5px">
        <b>${AS.esc(c.actor)}</b> <span style="color:var(--muted)">${AS.esc(c.role_label)} · ${AS.esc(c.at)}</span><br>${AS.esc(c.text)}
      </div>`);
    $('reviewActions').innerHTML = listHtml(d.actions || [], '조치 이력 없음 — 자동 수집 증적의 대응 내용을 기록하세요', a =>
      `<div style="font-size:11.5px;padding:7px 10px;background:#f8fafc;border-radius:8px;margin-bottom:5px">
        <b>${AS.esc(a.actor)}</b> <span class="badge b-info" style="font-size:9.5px">${AS.esc(a.action_status)}</span>
        <span style="color:var(--muted)">${AS.esc(a.at)}</span><br>${AS.esc(a.detail)}
      </div>`);
    $('reviewHistory').innerHTML = listHtml(d.history || [], '결재 이력 없음', h =>
      `<div style="font-size:11px;padding:6px 10px;border-left:3px solid var(--blue);margin-bottom:5px">
        <b>${AS.esc(h.actor)}</b>(${AS.esc(h.role_label)}) ${AS.esc(ACTION_LABELS[h.action] || h.action)} → ${AS.esc(h.to_label)}
        <span style="color:var(--muted)">${AS.esc(h.at)}</span>
        ${h.comment ? `<br><span style="color:var(--muted)">“${AS.esc(h.comment)}”</span>` : ''}
        <span class="mono" style="color:var(--muted);font-size:9.5px"> · ${AS.esc(h.hash)}</span>
      </div>`);
  }

  async function post(url, body) {
    return AS.api(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function submitTransition(action) {
    const actor = $('reviewActor').value.trim();
    if (!actor) { showMsg('처리자 이름을 입력하세요.', true); return; }
    try {
      await post(`/api/audit/evidence/${encodeURIComponent(curId)}/review`, {
        action, actor, role: $('reviewRole').value,
        comment: $('reviewComment').value.trim(),
      });
      showMsg('처리됐습니다 — 원장에 불변 기록됐습니다.', false);
      $('reviewComment').value = '';
      await load();
    } catch (e) { showMsg(`실패: ${e.message || e}`, true); }
  }

  async function submitComment() {
    const actor = $('reviewActor').value.trim() || '담당자';
    const text = $('commentText').value.trim();
    if (!text) return;
    try {
      await post(`/api/audit/evidence/${encodeURIComponent(curId)}/comment`, {
        actor, role: 'OWNER', text });
      $('commentText').value = '';
      await load();
    } catch (e) { showMsg(`코멘트 실패: ${e.message || e}`, true); }
  }

  async function submitAction() {
    const actor = $('reviewActor').value.trim() || '담당자';
    const detail = $('actionDetail').value.trim();
    if (!detail) return;
    try {
      await post(`/api/audit/evidence/${encodeURIComponent(curId)}/action`, {
        actor, action_type: '조치', detail, status: $('actionStatus').value });
      $('actionDetail').value = '';
      await load();
    } catch (e) { showMsg(`조치 기록 실패: ${e.message || e}`, true); }
  }

  document.addEventListener('click', e => {
    const b = e.target.closest('button[data-review]');
    if (!b) return;
    e.preventDefault();
    e.stopPropagation();
    curId = b.dataset.review;
    modal.hidden = false;
    $('reviewMsg').style.display = 'none';
    $('reviewStage').textContent = '불러오는 중…';
    load().catch(err => { $('reviewStage').textContent = `조회 실패: ${err.message}`; });
  });
  $('reviewClose').addEventListener('click', () => { modal.hidden = true; });
  modal.addEventListener('click', e => { if (e.target === modal) modal.hidden = true; });
  $('commentBtn').addEventListener('click', submitComment);
  $('actionBtn').addEventListener('click', submitAction);
})();
