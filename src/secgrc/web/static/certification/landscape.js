/* Control Landscape — 도메인→하위분야→통제 3단계 인터랙티브 트리.
 * 도메인 클릭 → 하위분야/통제 확장(zoom), 통제 클릭 → 상세 워크스페이스 이동.
 */
class ControlLandscape {
  constructor(containerId, opts = {}) {
    this.el = document.getElementById(containerId);
    this.zoomed = null; // 현재 확장된 도메인 id
    this.opts = opts;
    this.data = null;
  }

  async load() {
    this.data = await AS.api('/api/audit/landscape');
    this.render();
  }

  render() {
    const d = this.data;
    if (!d) return;
    let html = '<div class="domain-row" role="list">';
    for (const dom of d.domains) {
      const c = dom.counts;
      html += `
        <button class="domain-card ${this.zoomed === dom.id ? 'zoomed' : ''}"
                role="listitem" data-domain="${AS.esc(dom.id)}"
                aria-label="${AS.esc(dom.name)} ${dom.count}개 통제, 준비율 ${dom.ready_pct}%">
          <div style="display:flex;justify-content:space-between;align-items:baseline">
            <div class="dname">${AS.esc(dom.name)}</div>
            <div class="mono" style="font-size:11px;color:var(--muted)">${dom.count}개</div>
          </div>
          <div class="dmeta">준비율 ${dom.ready_pct}% · <span style="color:var(--green)">READY ${c.READY}</span> ·
            <span style="color:var(--amber)">PARTIAL ${c.PARTIAL}</span> ·
            <span style="color:var(--red)">MISSING ${c.MISSING}</span> ·
            <span style="color:var(--purple)">CONFLICT ${c.CONFLICT}</span></div>
          <div class="bar" aria-hidden="true">
            <i class="seg-READY" style="width:${c.READY / dom.count * 100}%"></i>
            <i class="seg-PARTIAL" style="width:${c.PARTIAL / dom.count * 100}%"></i>
            <i class="seg-MISSING" style="width:${c.MISSING / dom.count * 100}%"></i>
            <i class="seg-CONFLICT" style="width:${c.CONFLICT / dom.count * 100}%"></i>
          </div>
          <div class="dcounts">
            <span style="color:var(--green)">■ ${c.READY}</span>
            <span style="color:var(--amber)">■ ${c.PARTIAL}</span>
            <span style="color:var(--red)">■ ${c.MISSING}</span>
            <span style="color:var(--purple)">■ ${c.CONFLICT}</span>
          </div>
        </button>`;
    }
    html += '</div>';

    if (this.zoomed) {
      const dom = d.domains.find(x => x.id === this.zoomed);
      if (dom) {
        html += `<div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
          <div style="font-size:12.5px;font-weight:700">${AS.esc(dom.name)} — 하위 분야</div>
          <button class="tb-btn" data-zoomout style="font-size:11.5px;padding:5px 10px">← 전체 보기</button>
        </div>`;
        for (const sub of dom.sub) {
          html += `<div class="sub-label">${AS.esc(sub.sub_id)} ${AS.esc(sub.name)} <span class="cnt">${sub.count}개 통제</span></div>`;
          html += '<div class="subgrid">';
          for (const c of sub.controls) {
            html += `
              <button class="ctrl-node st-${AS.esc(c.state)}" data-control="${AS.esc(c.control_id)}"
                      aria-label="${AS.esc(c.control_id)} ${AS.esc(c.name)} 상태 ${AS.esc(AS.STATE_LABEL[c.state] || c.state)}">
                <div class="cid">${AS.esc(c.control_id)}${c.synthetic ? ' ·demo' : ''}</div>
                <div class="cname">${AS.esc(c.name)}</div>
                <div class="cev">증적 ${c.evidence_pct}%</div>
              </button>`;
          }
          html += '</div>';
        }
      }
    }
    this.el.innerHTML = html;
    this.bind();
  }

  bind() {
    this.el.querySelectorAll('.domain-card').forEach(el =>
      el.addEventListener('click', () => {
        this.zoomed = this.zoomed === el.dataset.domain ? null : el.dataset.domain;
        this.render();
      }));
    this.el.querySelectorAll('.ctrl-node').forEach(el =>
      el.addEventListener('click', () =>
        AS.go(`/controls/${el.dataset.control}`)));
    const out = this.el.querySelector('[data-zoomout]');
    if (out) out.addEventListener('click', () => { this.zoomed = null; this.render(); });
  }
}

// ?state= 필터 지원: 랜드스케이프에서 해당 상태만 강조
function applyStateFilter(state) {
  if (!state) return;
  document.querySelectorAll('.ctrl-node').forEach(n => {
    const st = [...n.classList].find(c => c.startsWith('st-'))?.slice(3);
    n.style.opacity = (!st || st === state) ? '1' : '0.28';
  });
}
