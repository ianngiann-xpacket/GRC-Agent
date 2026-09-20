/* Audit Replay — 스크립트 기반 심사원 상호작용 시뮬레이션.
 * 재생/일시정지/이전/다음/처음부터/증적·지적사항 점프 지원.
 */
class AuditReplay {
  constructor(stageId, pillsId, ctlId) {
    this.stage = document.getElementById(stageId);
    this.pills = document.getElementById(pillsId);
    this.ctl = document.getElementById(ctlId);
    this.scenario = null; this.idx = 0; this.timer = null;
  }

  async init() {
    this.scenario = await AS.api('/api/audit/replay');
    this.renderControls(); this.renderStep(0);
  }

  renderControls() {
    this.pills.innerHTML = this.scenario.steps.map(s => `
      <button class="step-pill" data-step="${s.idx}" aria-label="단계 ${s.idx + 1}">${s.idx + 1}</button>`).join('');
    this.pills.querySelectorAll('.step-pill').forEach(b =>
      b.addEventListener('click', () => this.jump(+b.dataset.step)));
    this.ctl.innerHTML = `
      <button class="rbtn primary" data-a="play">▶ 재생</button>
      <button class="rbtn" data-a="pause">⏸ 일시정지</button>
      <button class="rbtn" data-a="prev">← 이전</button>
      <button class="rbtn" data-a="next">다음 →</button>
      <button class="rbtn" data-a="restart">↺ 처음부터</button>`;
    this.ctl.querySelectorAll('[data-a]').forEach(b =>
      b.addEventListener('click', () => this.action(b.dataset.a)));
  }

  action(a) {
    if (a === 'play') { this.pause(); this.timer = setInterval(() => this.next(), 2600); }
    if (a === 'pause') this.pause();
    if (a === 'prev') this.jump(Math.max(0, this.idx - 1));
    if (a === 'next') this.next();
    if (a === 'restart') { this.pause(); this.jump(0); }
  }
  pause() { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
  next() {
    if (this.idx >= this.scenario.steps.length - 1) { this.pause(); return; }
    this.jump(this.idx + 1);
  }
  jump(i) { this.idx = i; this.renderStep(i); }

  renderStep(i) {
    const shown = this.scenario.steps.slice(0, i + 1);
    this.stage.innerHTML = shown.map(s => {
      const payload = s.payload ? this.renderPayload(s.payload) : '';
      return `<div class="replay-msg ${AS.esc(s.actor)}">
        <div style="flex:1">
          <div class="who">${s.actor === 'auditor' ? '👤 심사원' : '🖥 시스템'} · ${AS.esc(s.kind)}</div>
          <div class="body"><strong>${AS.esc(s.text)}</strong></div>
          <div class="detail">${AS.esc(s.detail)}</div>
          ${payload}
        </div></div>`;
    }).join('');
    this.pills.querySelectorAll('.step-pill').forEach((b, j) => {
      b.classList.toggle('done', j < i);
      b.classList.toggle('now', j === i);
    });
    this.stage.scrollTop = this.stage.scrollHeight;
  }

  renderPayload(p) {
    let html = '<div style="margin-top:8px;padding:10px;background:#fff;border:1px solid var(--border);border-radius:8px;font-size:11.5px">';
    if (p.population !== undefined) {
      html += `<div class="mono">모집단 ${p.population}명 · 기간 ${AS.esc(p.period)} · 출처 ${AS.esc(p.source)}</div>`;
      html += `<div style="margin-top:4px;color:var(--muted)">${(p.items || []).map(AS.esc).join(' · ')}</div>`;
    }
    if (p.disabled !== undefined)
      html += `<div class="mono">비활성화 ${p.disabled} · <span style="color:var(--red)">활성 잔존 ${p.active}</span> (${AS.esc(p.source)})</div>`;
    if (p.matched !== undefined)
      html += `<div class="mono">대사 일치 ${p.matched}건 · <span style="color:var(--red);font-weight:700">예외 ${p.exception}건</span></div>`;
    if (p.exceptions) {
      html += '<table class="tbl" style="margin-top:6px"><thead><tr><th>사용자</th><th>퇴직일</th><th>계정</th><th>상태</th><th>경과일</th></tr></thead><tbody>';
      for (const e of p.exceptions)
        html += `<tr><td>${AS.esc(e.user)}</td><td class="mono">${AS.esc(e.left)}</td><td class="mono">${AS.esc(e.account)}</td><td><span class="badge b-MISSING">${AS.esc(e.status)}</span></td><td class="mono" style="color:var(--red)">${AS.esc(e.days_over)}일</td></tr>`;
      html += '</tbody></table>';
    }
    if (p.evidence_id)
      html += `<div class="mono">증적 ${AS.esc(p.evidence_id)} · 해시체인 ${p.chain_valid ? '✓무결' : '✗손상'} · <a href="${AS.url('/evidence')}" style="color:var(--blue)">원장 보기 →</a></div>`;
    if (p.finding)
      html += `<div class="mono" style="margin-top:4px">지적사항 <a href="${AS.url('/findings')}" style="color:var(--blue)">${AS.esc(p.finding)} →</a>${p.action_status ? ` · 조치 ${AS.esc(p.action_status)} · 기한 ${AS.esc(p.due)}` : ''}</div>`;
    return html + '</div>';
  }
}
