/* Audit Time Machine — 과거 시점 스냅샷으로 화면 상태 전환.
 * 스냅샷은 /api/audit/snapshot?date= 에서 제공 (백엔드 계약, demo 데이터 표기).
 */
class AuditTimeMachine {
  constructor(mountId) {
    this.mount = document.getElementById(mountId);
    this.snapshots = [];
    this.current = null;
  }

  async init() {
    this.snapshots = await AS.api('/api/audit/snapshots');
    this.renderTrack();
    const saved = AS.get('date');
    const initial = saved
      ? this.snapshots.find(s => s.date === saved)
      : this.snapshots[this.snapshots.length - 1];
    await this.select(initial.date);
  }

  renderTrack() {
    const buttons = this.snapshots.map(s => `
      <button class="tm-stop" data-date="${AS.esc(s.date)}" role="option"
              aria-label="${AS.esc(s.label)} ${AS.esc(s.date)}">
        <div class="dot"></div><div class="lb">${AS.esc(s.label)}<br>${AS.esc(s.date.slice(5))}</div>
      </button>`).join('');
    this.mount.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="card-t">◷ Audit Time Machine</div>
        <span class="demo-tag">데모 스냅샷</span>
      </div>
      <div class="tm-track" role="listbox" aria-label="시점 선택">${buttons}</div>
      <div id="tmResult" style="margin-top:12px"></div>`;
    this.mount.querySelectorAll('.tm-stop').forEach(b =>
      b.addEventListener('click', () => this.select(b.dataset.date)));
  }

  async select(date) {
    this.mount.querySelectorAll('.tm-stop').forEach(b =>
      b.classList.toggle('on', b.dataset.date === date));
    const snap = await AS.api(`/api/audit/snapshot?date=${encodeURIComponent(date)}`);
    this.current = snap;
    this.renderResult(snap);
    // URL 상태 보존
    const p = new URLSearchParams(location.search); p.set('date', date);
    history.replaceState(null, '', `${location.pathname}?${p}`);
  }

  renderResult(s) {
    const stateChip = st =>
      `<span class="badge b-${AS.esc(st)}" style="margin:1px 2px">${AS.esc(AS.STATE_LABEL[st] || st)}</span>`;
    const changes = Object.entries(s.control_states).map(([cid, st]) =>
      `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f1f5f9;font-size:12px">
        <a href="${AS.url('/controls/' + encodeURIComponent(cid), { date: s.date })}" class="mono" style="color:var(--blue)">${AS.esc(cid)}</a>
        ${stateChip(st)}
      </div>`).join('');
    document.getElementById('tmResult').innerHTML = `
      <div class="grid-3" style="margin-bottom:10px">
        <div style="text-align:center;padding:10px;background:#f8fafc;border-radius:8px">
          <div style="font-size:10.5px;color:var(--muted);font-weight:600">준비도 (${s.date})</div>
          <div class="mono" style="font-size:22px;font-weight:800;color:var(--blue)">${s.readiness}%</div>
          <div style="font-size:10.5px;color:var(--muted)">${s.ready}/${s.total} 통제</div>
        </div>
        <div style="text-align:center;padding:10px;background:#f8fafc;border-radius:8px">
          <div style="font-size:10.5px;color:var(--muted);font-weight:600">증적 확보율</div>
          <div class="mono" style="font-size:22px;font-weight:800;color:var(--purple)">${s.evidence_pct}%</div>
          <div style="font-size:10.5px;color:var(--muted)">GAP ${s.gaps}건</div>
        </div>
        <div style="text-align:center;padding:10px;background:#f8fafc;border-radius:8px">
          <div style="font-size:10.5px;color:var(--muted);font-weight:600">미해결 지적사항</div>
          <div class="mono" style="font-size:22px;font-weight:800;color:var(--red)">${s.findings_open}</div>
          <div style="font-size:10.5px;color:var(--muted)">${AS.esc(s.note)}</div>
        </div>
      </div>
      <div style="font-size:11.5px;font-weight:700;color:var(--muted);margin-bottom:4px">변경된 통제 상태</div>
      ${changes || '<div style="font-size:12px;color:var(--muted)">변경 없음</div>'}`;
  }
}
