/* Collection Status — Prowler CSPM 실행 패널.
 * 라이브 스캔(Docker 격리) + 결과 JSON 업로드(replay) + 실행 이력 조회.
 * 모든 동적 값은 AS.esc()로 이스케이프.
 */
(() => {
  const capsEl = document.getElementById('prowlerCaps');
  const runsBody = document.getElementById('prowlerRuns');
  const detailEl = document.getElementById('prowlerDetail');
  const runBtn = document.getElementById('prowlerRunBtn');
  const projInput = document.getElementById('prowlerProject');
  const replayInput = document.getElementById('prowlerReplayFile');
  const msgEl = document.getElementById('prowlerMsg');
  if (!capsEl || !runsBody) return;

  let pollTimer = null;

  function msg(text, kind) {
    msgEl.style.display = 'block';
    msgEl.style.background = kind === 'error' ? 'var(--red-soft, #fef2f2)'
      : kind === 'ok' ? 'var(--green-soft, #f0fdf4)' : 'var(--blue-soft, #eff6ff)';
    msgEl.style.color = kind === 'error' ? 'var(--red)' : kind === 'ok' ? 'var(--green)' : 'var(--blue)';
    msgEl.innerHTML = text;
  }

  function capBadge(label, ok, note) {
    const cls = ok ? 'b-PASS' : 'b-FAIL';
    return `<span class="badge ${cls}" style="font-size:10px" title="${AS.esc(note || '')}">${AS.esc(label)} ${ok ? '✓' : '✕'}</span>`;
  }

  function renderCaps(c) {
    capsEl.innerHTML =
      capBadge('Docker', c.docker_running, c.docker_binary ? (c.docker_running ? '데몬 실행 중' : 'Docker Desktop을 시작하세요') : 'Docker 미설치') + ' ' +
      capBadge('GCP 인증(ADC)', c.adc_present, c.adc_present ? 'application_default_credentials.json' : 'gcloud auth application-default login 필요') + ' ' +
      capBadge('라이브 스캔', c.live_scan_available, c.live_scan_available ? '실행 가능' : 'Docker + ADC 모두 필요 — 또는 결과 JSON 업로드 사용');
    if (runBtn) runBtn.disabled = !c.live_scan_available;
  }

  function statusBadge(s) {
    const cls = s === 'COMPLETED' ? 'PASS' : s === 'RUNNING' || s === 'PENDING' ? 'IN_PROGRESS' : 'FAIL';
    return `<span class="badge b-${cls}" style="font-size:10px">${AS.esc(s)}</span>`;
  }

  function renderRuns(data) {
    const ops = (data.ops || []).filter(o => o.status === 'RUNNING' || o.status === 'FAILED');
    const rows = [];
    for (const o of ops) {
      rows.push(`<tr>
        <td class="mono" style="font-size:11px">${AS.esc(o.op_id)}${o.run_id ? ' → ' + AS.esc(o.run_id) : ''}</td>
        <td>${statusBadge(o.status)}${o.error ? ` <span style="font-size:10px;color:var(--red)">${AS.esc(o.error)}</span>` : ''}</td>
        <td class="mono" colspan="2" style="font-size:11px">${AS.esc(o.project_id || '')}${o.record_count != null ? ' · ' + o.record_count + '건' : ''}</td>
        <td class="mono" style="font-size:11px">${AS.esc((o.started_at || '').slice(5, 19).replace('T', ' '))}</td>
        <td></td>
      </tr>`);
    }
    for (const r of (data.runs || [])) {
      rows.push(`<tr>
        <td class="mono" style="font-size:11px">${AS.esc(r.run_id)}</td>
        <td>${statusBadge(r.status)}</td>
        <td class="mono">${r.record_count}</td>
        <td class="mono" style="font-size:11px">${r.accepted}/${r.rejected}</td>
        <td class="mono" style="font-size:11px">${AS.esc((r.started_at || '').slice(5, 19).replace('T', ' '))}</td>
        <td><button type="button" class="tb-btn" style="font-size:10.5px;padding:2px 8px" data-run="${AS.esc(r.run_id)}">리포트</button></td>
      </tr>`);
    }
    runsBody.innerHTML = rows.length ? rows.join('')
      : '<tr><td colspan="6" class="text-muted" style="font-size:12px">실행 이력이 없습니다.</td></tr>';
    runsBody.querySelectorAll('button[data-run]').forEach(b =>
      b.addEventListener('click', () => loadDetail(b.dataset.run)));

    // 진행 중인 op이 있으면 폴링 유지
    const running = ops.some(o => o.status === 'RUNNING');
    if (running && !pollTimer) pollTimer = setInterval(load, 5000);
    if (!running && pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  async function load() {
    try {
      const data = await AS.api('/api/audit/collection/prowler');
      renderCaps(data.capabilities || {});
      renderRuns(data);
    } catch (e) {
      capsEl.textContent = 'Prowler 상태 조회 실패 — ' + e.message;
    }
  }

  async function loadDetail(runId) {
    detailEl.innerHTML = '<span style="font-size:11.5px;color:var(--muted)">리포트 로딩 중…</span>';
    try {
      const r = await AS.api(`/api/audit/collection/prowler/runs/${encodeURIComponent(runId)}`);
      const sev = Object.entries(r.findings_by_severity || {}).map(([k, v]) => `${AS.esc(k)} ${v}`).join(' · ') || '—';
      const stat = Object.entries(r.findings_by_status || {}).map(([k, v]) => `${AS.esc(k)} ${v}`).join(' · ') || '—';
      const svc = Object.entries(r.findings_by_service || {}).map(([k, v]) => `${AS.esc(k)} ${v}`).join(' · ') || '—';
      const fails = (r.failed_checks || []).map(f =>
        `<tr><td class="mono" style="font-size:11px">${AS.esc(f.check_id)}</td>
         <td><span class="badge b-FAIL" style="font-size:9.5px">${AS.esc(f.severity)}</span></td>
         <td class="mono">${f.count}</td>
         <td style="font-size:11px">${AS.esc(f.description)}</td></tr>`).join('');
      detailEl.innerHTML = `<div class="card" style="border-color:var(--blue);background:var(--blue-soft,#eff6ff)">
        <div class="card-b" style="font-size:12px">
          <div style="font-weight:700;margin-bottom:6px">${AS.esc(r.run_id)} — ${AS.esc(r.status)} · 매니페스트 해시 <code>${AS.esc((r.manifest || {}).manifest_hash || '').slice(0, 16)}…</code></div>
          <div style="margin-bottom:4px"><b>심각도</b> ${sev}</div>
          <div style="margin-bottom:4px"><b>상태</b> ${stat}</div>
          <div style="margin-bottom:6px"><b>서비스</b> ${svc}</div>
          ${fails ? `<table class="tbl" style="margin-top:6px"><thead><tr><th>체크</th><th>심각도</th><th>건수</th><th>설명</th></tr></thead><tbody>${fails}</tbody></table>` : ''}
          <div style="font-size:10.5px;color:var(--muted);margin-top:6px">원시·정규화 결과는 data/prowler/ 아래 run 디렉터리에 보존되며, 매니페스트 해시로 무결성을 검증할 수 있습니다. 파인딩은 관측값(non-authoritative)이며 통제 판정은 별도 분석이 필요합니다.</div>
        </div></div>`;
    } catch (e) {
      detailEl.innerHTML = `<span style="font-size:11.5px;color:var(--red)">리포트 조회 실패 — ${AS.esc(e.message)}</span>`;
    }
  }

  if (runBtn) runBtn.addEventListener('click', async () => {
    const pid = (projInput.value || '').trim();
    if (!pid) { msg('GCP 프로젝트 ID를 입력하세요.', 'error'); projInput.focus(); return; }
    runBtn.disabled = true;
    try {
      const d = await AS.api('/api/audit/collection/prowler/run', {
        method: 'POST', body: JSON.stringify({ project_id: pid }),
      });
      msg(`스캔 시작 — <code>${AS.esc(d.op_id)}</code> 실행 중입니다. GCP 프로젝트 규모에 따라 수 분 걸릴 수 있습니다.`, 'ok');
      load();
      if (!pollTimer) pollTimer = setInterval(load, 5000);
    } catch (e) {
      let detail = e.message;
      msg(`라이브 스캔을 시작할 수 없습니다 — ${AS.esc(detail)}. 결과 JSON 업로드 경로를 사용할 수 있습니다.`, 'error');
      runBtn.disabled = false;
    }
  });

  if (replayInput) replayInput.addEventListener('change', async () => {
    const f = replayInput.files[0];
    replayInput.value = '';
    if (!f) return;
    const pid = (projInput.value || '').trim() || 'uploaded-scan';
    msg(`결과 파일 정규화 중 — ${AS.esc(f.name)}…`, 'info');
    try {
      const res = await fetch(`/api/audit/collection/prowler/replay?project_id=${encodeURIComponent(pid)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-File-Name': encodeURIComponent(f.name),
          'X-Evidence-Upload': '1',
        },
        body: f,
      });
      const d = await res.json();
      if (res.ok && d.ok) {
        msg(`정규화 완료 — <code>${AS.esc(d.run_id)}</code>: 파인딩 ${d.record_count}건 (수용 ${d.accepted} / 거부 ${d.rejected}). 원장에 기록되었습니다.`, 'ok');
        load();
      } else {
        msg(`정규화 실패 — ${AS.esc(d.detail || d.error || ('HTTP ' + res.status))}`, 'error');
      }
    } catch (e) {
      msg('업로드 실패 — ' + AS.esc(e.message), 'error');
    }
  });

  load();
})();
