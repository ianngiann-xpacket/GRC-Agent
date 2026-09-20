/* Evidence Intake — 실제 파일 업로드.
 * raw-body POST /api/audit/evidence/upload (multipart 불필요).
 * X-Evidence-Upload 커스텀 헤더 필수 — CSRF 방어의 일부.
 * 모든 동적 값은 AS.esc()로 이스케이프.
 */
(() => {
  const zone = document.getElementById('dropZone');
  const input = document.getElementById('fileInput');
  const btn = document.getElementById('uploadBtn');
  const status = document.getElementById('uploadStatus');
  const controlSel = document.getElementById('intakeControl');
  const typeSel = document.getElementById('intakeType');
  const tbody = document.getElementById('intakeResults');
  if (!zone || !input) return;

  let pendingFile = null;
  const TEXT_EXT = /\.(txt|csv|html|htm|md|log|json)$/i;
  const suggBox = document.getElementById('suggestBox');

  function setStatus(msg, kind) {
    status.style.display = 'block';
    status.style.background = kind === 'error' ? 'var(--red-soft, #fef2f2)'
      : kind === 'ok' ? 'var(--green-soft, #f0fdf4)' : 'var(--blue-soft, #eff6ff)';
    status.style.color = kind === 'error' ? 'var(--red)' : kind === 'ok' ? 'var(--green)' : 'var(--blue)';
    status.innerHTML = msg;
  }

  function renderSuggestions(data) {
    if (!suggBox) return;
    const cands = data.candidates || [];
    if (!cands.length) {
      suggBox.innerHTML = `<div style="font-size:11.5px;color:var(--muted)">자동 매핑 후보가 없습니다 — 통제 항목을 직접 선택해 주세요.</div>`;
      return;
    }
    const conf = { high: '높음', medium: '보통', low: '낮음' }[data.confidence] || data.confidence;
    suggBox.innerHTML = `<div style="font-size:11.5px;font-weight:700;color:var(--purple);margin-bottom:6px">
        ⓘ 자동 추천 (신뢰도 ${AS.esc(conf)}) — 최종 매핑은 확인 후 확정됩니다</div>` +
      cands.map((c, i) => `<button type="button" class="sugg-btn sugg-ctl" data-cid="${AS.esc(c.control_id)}"
          style="font-size:11.5px">${i === 0 ? '★ ' : ''}${AS.esc(c.control_id)} ${AS.esc(c.name)}
          <span style="color:var(--muted)">(${c.matched.map(AS.esc).join('·')})</span></button>`).join('');
    suggBox.querySelectorAll('.sugg-ctl').forEach(b =>
      b.addEventListener('click', () => {
        controlSel.value = b.dataset.cid;
        suggBox.querySelectorAll('.sugg-ctl').forEach(x => x.style.borderColor = 'var(--border)');
        b.style.borderColor = 'var(--blue)';
      }));
  }

  async function suggest(file) {
    let sample = '';
    if (TEXT_EXT.test(file.name)) {
      try { sample = await file.slice(0, 65536).text(); } catch (_) { /* 바이너리 판독 실패 시 파일명만 사용 */ }
    }
    try {
      const data = await AS.api('/api/audit/evidence/suggest', {
        method: 'POST',
        body: JSON.stringify({ file_name: file.name, sample }),
      });
      renderSuggestions(data);
      const top = (data.candidates || [])[0];
      if (top && ['high', 'medium'].includes(data.confidence)) {
        controlSel.value = top.control_id;
        setStatus(`선택됨: <strong>${AS.esc(file.name)}</strong> — 추천 통제 <strong>${AS.esc(top.control_id)} ${AS.esc(top.name)}</strong> 자동 선택됨`, 'info');
      }
    } catch (_) { /* 추천 실패 시 수동 선택 유지 */ }
  }

  function pick(file) {
    pendingFile = file;
    zone.querySelector('div:nth-child(2)').textContent = file.name;
    zone.querySelector('div:nth-child(3)').textContent =
      `${(file.size / 1024).toFixed(1)} KB — 통제 항목을 선택한 뒤 업로드`;
    btn.disabled = false;
    btn.textContent = '업로드';
    setStatus(`선택됨: <strong>${AS.esc(file.name)}</strong> (${(file.size / 1024).toFixed(1)} KB)`, 'info');
    suggest(file);
  }

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  input.addEventListener('change', () => { if (input.files[0]) pick(input.files[0]); });

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.style.borderColor = 'var(--blue)'; });
  zone.addEventListener('dragleave', () => { zone.style.borderColor = 'var(--border-strong)'; });
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.style.borderColor = 'var(--border-strong)';
    if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]);
  });

  function resultRow(name, control, sensitive, hash, ok, note) {
    return `<tr style="background:#f0fdf4">
      <td style="font-weight:600;font-size:12px">${AS.esc(name)} <span class="badge b-info" style="font-size:9.5px">방금 업로드</span></td>
      <td class="mono" style="font-size:11px">${AS.esc(control)}</td>
      <td><span class="badge b-${sensitive ? 'FAIL' : 'PASS'}">${sensitive ? '검출' : '없음'}</span></td>
      <td class="mono" style="font-size:10.5px" title="${AS.esc(hash || '')}">${AS.esc((hash || '—').slice(0, 12))}…</td>
      <td><span class="badge b-${ok ? 'PASS' : 'FAIL'}">${AS.esc(note)}</span></td>
    </tr>`;
  }

  function resetForm() {
    pendingFile = null;
    input.value = '';
    zone.querySelector('div:nth-child(2)').textContent = '파일을 드래그하거나 클릭하여 업로드';
    zone.querySelector('div:nth-child(3)').textContent =
      'PDF · XLSX · DOCX · PNG · HWP · HTML · TXT · CSV — 최대 10MB, 업로드 즉시 민감정보 자동 검사';
    if (suggBox) suggBox.innerHTML = '';
    btn.disabled = true;
    btn.textContent = '파일 선택 후 업로드 가능';
  }

  async function upload() {
    if (!pendingFile) return;
    const controlId = controlSel.value;
    if (!controlId) {
      setStatus('통제 항목을 먼저 선택해 주세요.', 'error');
      controlSel.focus();
      return;
    }
    btn.disabled = true;
    btn.textContent = '업로드 중…';
    try {
      const res = await fetch(
        `/api/audit/evidence/upload?control_id=${encodeURIComponent(controlId)}&doc_type=${encodeURIComponent(typeSel.value)}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-File-Name': encodeURIComponent(pendingFile.name),
            'X-Evidence-Upload': '1',
          },
          body: pendingFile,
        });
      const data = await res.json();
      if (res.ok && data.ok) {
        tbody.insertAdjacentHTML('afterbegin',
          resultRow(data.file_name, data.control_id, false, data.sha256, true,
            `통과 · 원장 ${data.record_id.slice(0, 12)}`));
        setStatus(
          `✅ <strong>${AS.esc(data.file_name)}</strong> 등록 완료 — 증적 ID <code>${AS.esc(data.evidence_id)}</code>, ` +
          `SHA-256 <code>${AS.esc(data.sha256.slice(0, 16))}…</code>, 해시체인 ${data.chain_valid ? '무결 ✓' : '손상 ✗'}`, 'ok');
        resetForm();  // 같은 파일의 중복 업로드 방지
      } else if (data.blocked) {
        tbody.insertAdjacentHTML('afterbegin',
          resultRow(data.file_name || pendingFile.name, controlId, true, data.sha256, false, '차단됨'));
        setStatus(
          `🚫 <strong>민감정보 검출로 차단</strong> — ${AS.esc((data.detected || []).join(', '))}. ` +
          `파일은 저장되지 않았으며 차단 사실이 원장에 기록되었습니다.`, 'error');
      } else {
        setStatus(`업로드 실패: ${AS.esc(data.error || `HTTP ${res.status}`)}`, 'error');
      }
    } catch (e) {
      setStatus('네트워크 오류로 업로드하지 못했습니다.', 'error');
    } finally {
      if (pendingFile) {  // 성공 시 resetForm이 버튼을 비활성화 — 실패 시에만 재시도 가능하게 복원
        btn.disabled = false;
        btn.textContent = '업로드';
      }
    }
  }

  btn.addEventListener('click', upload);
})();
