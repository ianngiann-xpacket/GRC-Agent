/* SVG 라인 차트 — 의존성 없는 경량 렌더러 (백엔드 시계열 데이터만 사용) */
function renderLineChart(el, trend) {
  if (!el || !trend) return;
  const W = el.clientWidth || 640, H = 200, pad = { t: 14, r: 14, b: 26, l: 36 };
  const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
  const all = trend.series.flatMap(s => s.data);
  const max = Math.max(...all, 1), min = Math.min(...all, 0);
  const span = (max - min) || 1;
  const x = i => pad.l + (i / (trend.labels.length - 1)) * iw;
  const y = v => pad.t + ih - ((v - min) / span) * ih;

  let svg = `<svg width="100%" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="추세 차트">`;
  // gridlines
  for (let g = 0; g <= 4; g++) {
    const gy = pad.t + (ih / 4) * g;
    const gv = Math.round(max - (span / 4) * g);
    svg += `<line x1="${pad.l}" y1="${gy}" x2="${W - pad.r}" y2="${gy}" stroke="#eef2f7"/>`;
    svg += `<text x="${pad.l - 6}" y="${gy + 3}" font-size="9" fill="#94a3b8" text-anchor="end" font-family="JetBrains Mono">${gv}</text>`;
  }
  // x labels (3개만)
  const step = Math.ceil(trend.labels.length / 4);
  trend.labels.forEach((lb, i) => {
    if (i % step === 0) svg += `<text x="${x(i)}" y="${H - 8}" font-size="9" fill="#94a3b8" text-anchor="middle" font-family="JetBrains Mono">${AS.esc(lb)}</text>`;
  });
  // series — color는 안전 문자만 허용 (SVG 속성 삽입 방어)
  const safeColor = c => String(c || '').replace(/[^#0-9a-zA-Z(),.% -]/g, '');
  for (const s of trend.series) {
    const color = safeColor(s.color);
    const pts = s.data.map((v, i) => `${x(i)},${y(v)}`).join(' ');
    svg += `<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>`;
    const last = s.data[s.data.length - 1];
    svg += `<circle cx="${x(s.data.length - 1)}" cy="${y(last)}" r="3.5" fill="${color}"/>`;
  }
  svg += '</svg>';
  // legend
  svg += `<div style="display:flex;gap:14px;padding:6px 4px 0;font-size:11px;color:var(--muted)">` +
    trend.series.map(s =>
      `<span><span style="display:inline-block;width:9px;height:9px;border-radius:2px;background:${s.color};margin-right:5px"></span>${AS.esc(s.name)}</span>`
    ).join('') + (trend.demo ? '<span class="demo-tag" style="margin-left:auto">데모 데이터</span>' : '') + '</div>';
  el.innerHTML = svg;
}
