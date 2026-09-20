/* Evidence Intake — 실제 파일 업로드 (다중 파일 큐 + 통제 일괄 매핑).
 * raw-body POST /api/audit/evidence/upload (multipart 불필요).
 * X-Evidence-Upload 커스텀 헤더 필수 — CSRF 방어의 일부.
 * 모든 동적 값은 AS.esc()로 이스케이프.
 */
(() => {
  const zone = document.getElementById('dropZone');
  const input = document.getElementById('fileInput');
  const btn = document.getElementById('uploadBtn');
  const applyAllBtn = document.getElementById('applyAllBtn');
  const status = document.getElementById('uploadStatus');
  const controlSel = document.getElementById('intakeControl');
  const typeSel = document.getElementById('intakeType');
  const tbody = document.getElementById('intakeResults');
  const queueBox = document.getElementById('uploadQueue');
  const suggBox = document.getElementById('suggestBox');
  if (!zone || !input) return;

  const TEXT_EXT = /\.(txt|csv|html|htm|md|log|json)$/i;
  let queue = [];        // {file, ctlSel, statusEl, userSet}
  let uploading = false;

  function setStatus(msg, kind) {
    status.style.display = 'block';
    status.style.background = kind === 'error' ? 'var(--red-soft, #fef2f2)'
      : kind === 'ok' ? 'var(--green-soft, #f0fdf4)' : 'var(--blue-soft, #eff6ff)';
    status.style.color = kind === 'error' ? 'var(--red)' : kind === 'ok' ? 'var(--green)' : 'var(--blue)';
    status.innerHTML = msg;
  }

  function ctlSelect() {
    const s = document.createElement('select');
    s.className = 'tb-select';
    s.style.cssText = 'width:100%;font-size:11.5px;padding:5px 8px';
    s.innerHTML = controlSel.innerHTML;
    return s;
  }

  function renderQueue() {
    if (!queue.length) { queueBox.innerHTML = ''; return; }
    queueBox.innerHTML = `<div style="font-size:11.5px;font-weight:700;color:var(--text-2);margin-bottom:6px">
      업로드 대기 ${queue.length}개 — 추천 칩을 토글해 복수 통제에 매핑하거나 목록에서 추가하세요</div>`;
    queue.forEach((it, i) => {
      const row = document.createElement('div');
      row.style.cssText = 'padding:7px 10px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px;background:#fff';
      const top = document.createElement('div');
      top.style.cssText = 'display:grid;grid-template-columns:minmax(140px,1fr) 1.6fr auto;gap:8px;align-items:start';
      const name = document.createElement('div');
      name.style.cssText = 'min-width:0';
      name.innerHTML = `<div style="font-weight:600;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${AS.esc(it.file.name)}">${AS.esc(it.file.name)}</div>
        <div style="font-size:10.5px;color:var(--muted)">${(it.file.size / 1024).toFixed(1)} KB</div>`;
      // 매핑 셀 — 선택된 통제 칩 + 추가용 전체 목록
      const mapCell = document.createElement('div');
      it.selBox = document.createElement('div');
      it.selBox.style.cssText = 'display:flex;gap:4px;flex-wrap:wrap;margin-bottom:4px';
      it.ctlSel.style.fontSize = '11px';
      mapCell.appendChild(it.selBox);
      mapCell.appendChild(it.ctlSel);
      const right = document.createElement('div');
      right.style.cssText = 'display:flex;align-items:center;gap:6px';
      const st = document.createElement('span');
      st.className = 'badge b-info';
      st.style.fontSize = '10px';
      st.textContent = '대기';
      const rm = document.createElement('button');
      rm.type = 'button';
      rm.className = 'tb-btn';
      rm.style.cssText = 'font-size:10.5px;padding:3px 8px';
      rm.textContent = '✕';
      rm.setAttribute('aria-label', `${it.file.name} 대기열에서 제거`);
      rm.addEventListener('click', () => { queue.splice(i, 1); renderQueue(); refreshBtn(); });
      right.appendChild(st);
      right.appendChild(rm);
      it.statusEl = st;
      it.chipsEl = document.createElement('div');
      it.chipsEl.style.cssText = 'display:flex;gap:5px;flex-wrap:wrap;margin-top:6px';
      it.ctlSel.addEventListener('change', () => {
        if (it.ctlSel.value) {
          it.selected.add(it.ctlSel.value);
          it.ctlSel.value = '';
          it.userSet = true;
          syncChips(it);
        }
      });
      top.appendChild(name);
      top.appendChild(mapCell);
      top.appendChild(right);
      row.appendChild(top);
      row.appendChild(it.chipsEl);
      queueBox.appendChild(row);
      syncChips(it);
      renderChips(it);
    });
  }

  // 선택된 통제 칩 — 클릭하면 매핑 해제 (1개 증적→복수 통제 매핑은 심사상 정상 패턴)
  function renderSelected(it) {
    it.selBox.innerHTML = '';
    if (!it.selected.size) {
      it.selBox.innerHTML = '<span style="font-size:10.5px;color:var(--muted)">통제 미선택 — 추천 칩을 토글하거나 아래 목록에서 추가</span>';
      return;
    }
    for (const cid of it.selected) {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'tb-btn';
      chip.style.cssText = 'font-size:10.5px;padding:3px 8px;border-color:var(--blue);' +
        'background:var(--blue-soft);color:var(--blue);font-weight:700';
      chip.textContent = `${cid} ✕`;
      chip.title = `${cid} 매핑 해제`;
      chip.addEventListener('click', () => { it.selected.delete(cid); syncChips(it); });
      it.selBox.appendChild(chip);
    }
  }

  function syncChips(it) {
    renderSelected(it);
    (it.chipsEl ? it.chipsEl : { querySelectorAll: () => [] })
      .querySelectorAll('button[data-cid]').forEach(b => {
        const on = it.selected.has(b.dataset.cid);
        b.style.borderColor = on ? 'var(--blue)' : 'var(--border)';
        b.style.background = on ? 'var(--blue-soft)' : '';
        b.style.fontWeight = on ? '700' : '';
      });
  }

  // 파일별 추천 통제 칩 — 토글식 복수 선택 (추천 API 후보를 그대로 노출)
  function renderChips(it) {
    const box = it.chipsEl;
    if (!box) return;
    box.innerHTML = '';
    if (!it.cands) {
      const ld = document.createElement('span');
      ld.style.cssText = 'font-size:10px;color:var(--faint)';
      ld.textContent = '추천 분석 중…';
      box.appendChild(ld);
      return;
    }
    const cands = it.cands.slice(0, 3);
    if (!cands.length) {
      const none = document.createElement('span');
      none.style.cssText = 'font-size:10.5px;color:var(--muted)';
      none.textContent = it.suggErr
        ? '추천 분석 실패 — 위 목록에서 통제를 직접 선택하세요.'
        : '자동 추천 없음 — 파일명·본문에서 통제 키워드를 찾지 못했습니다. 위 목록에서 직접 선택하세요.';
      box.appendChild(none);
      return;
    }
    const lb = document.createElement('span');
    lb.style.cssText = 'font-size:10px;color:var(--purple);font-weight:700;align-self:center';
    lb.textContent = '추천:';
    box.appendChild(lb);
    cands.forEach((c, i) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'tb-btn';
      b.dataset.cid = c.control_id;
      b.style.cssText = 'font-size:10.5px;padding:3px 9px;white-space:nowrap' +
        (it.selected.has(c.control_id) ? ';border-color:var(--blue);background:var(--blue-soft);font-weight:700' : '');
      b.innerHTML = `${i === 0 ? '★ ' : ''}${AS.esc(c.control_id)} ${AS.esc(c.name)}` +
        (c.matched?.length ? ` <span style="color:var(--muted)">(${c.matched.map(AS.esc).join('·')})</span>` : '');
      b.title = `${c.control_id} ${c.name} — 추천 근거: ${(c.matched || []).join(', ') || '파일명 유사'} · 클릭하여 매핑 추가/해제`;
      b.addEventListener('click', () => {
        if (it.selected.has(c.control_id)) it.selected.delete(c.control_id);
        else it.selected.add(c.control_id);
        it.userSet = true;
        syncChips(it);
      });
      box.appendChild(b);
    });
  }

  function refreshBtn() {
    const n = queue.length;
    btn.disabled = !n || uploading;
    btn.textContent = n ? (n === 1 ? '업로드' : `${n}개 파일 업로드`) : '파일 선택 후 업로드 가능';
  }

  async function suggestFor(item) {
    let sample = '';
    if (TEXT_EXT.test(item.file.name)) {
      try { sample = await item.file.slice(0, 65536).text(); } catch (_) { /* 바이너리 판독 실패 시 파일명만 */ }
    }
    try {
      const data = await AS.api('/api/audit/evidence/suggest', {
        method: 'POST',
        body: JSON.stringify({ file_name: item.file.name, sample }),
      });
      item.cands = data.candidates || [];
      renderChips(item);
      const top = item.cands[0];
      if (top && ['high', 'medium'].includes(data.confidence) && !item.userSet) {
        item.selected.add(top.control_id);
        item.statusEl.textContent = `추천 ${top.control_id}`;
        item.statusEl.className = 'badge b-PARTIAL';
        item.statusEl.style.fontSize = '10px';
        syncChips(item);
        renderChips(item);
      }
    } catch (_) {
      item.cands = [];
      item.suggErr = true;
      renderChips(item);
    }
  }

  function pick(fileList) {
    const files = [...fileList].slice(0, 30);
    for (const file of files) {
      const item = { file, ctlSel: ctlSelect(), selected: new Set(), statusEl: null, userSet: false };
      queue.push(item);
      suggestFor(item);
    }
    renderQueue();
    refreshBtn();
    if (files.length) {
      setStatus(`<strong>${files.length}개 파일</strong> 대기 중 — 파일별 통제를 확인하거나, 아래 '전체 적용'으로 일괄 지정하세요.`, 'info');
    }
    if (suggBox) suggBox.innerHTML = '';
  }

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  input.addEventListener('change', () => { if (input.files.length) pick(input.files); input.value = ''; });

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.style.borderColor = 'var(--blue)'; });
  zone.addEventListener('dragleave', () => { zone.style.borderColor = 'var(--border-strong)'; });
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.style.borderColor = 'var(--border-strong)';
    if (e.dataTransfer.files.length) pick(e.dataTransfer.files);
  });

  // 일괄 매핑 — 상단 통제 선택을 대기 중인 전체 파일에 적용
  if (applyAllBtn) applyAllBtn.addEventListener('click', () => {
    if (!queue.length) { setStatus('먼저 파일을 선택해 주세요.', 'error'); return; }
    if (!controlSel.value) { setStatus('일괄 적용할 통제 항목을 먼저 선택해 주세요.', 'error'); controlSel.focus(); return; }
    queue.forEach(it => { it.selected.add(controlSel.value); it.userSet = true; syncChips(it); });
    setStatus(`통제 <strong>${AS.esc(controlSel.value)}</strong>를 대기 중인 ${queue.length}개 파일에 일괄 추가했습니다.`, 'info');
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

  function rowStatus(item, text, cls) {
    if (!item.statusEl) return;
    item.statusEl.textContent = text;
    item.statusEl.className = `badge b-${cls}`;
    item.statusEl.style.fontSize = '10px';
  }

  async function uploadOne(item) {
    const controlIds = [...item.selected];
    if (!controlIds.length) { rowStatus(item, '통제 미지정', 'FAIL'); return { ok: false, skip: true }; }
    const controlId = controlIds.join(',');
    rowStatus(item, '업로드 중…', 'IN_PROGRESS');
    try {
      const res = await fetch(
        `/api/audit/evidence/upload?control_id=${encodeURIComponent(controlId)}&doc_type=${encodeURIComponent(typeSel.value)}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-File-Name': encodeURIComponent(item.file.name),
            'X-Evidence-Upload': '1',
          },
          body: item.file,
        });
      const data = await res.json();
      if (res.ok && data.ok) {
        const n = (data.control_ids || []).length;
        tbody.insertAdjacentHTML('afterbegin',
          resultRow(data.file_name, (data.control_ids || [data.control_id]).join(' · '), false, data.sha256, true,
            `통과 · ${n}개 통제 매핑`));
        rowStatus(item, '완료 ✓', 'PASS');
        return { ok: true, id: data.evidence_id };
      }
      if (data.blocked) {
        tbody.insertAdjacentHTML('afterbegin',
          resultRow(data.file_name || item.file.name, controlId, true, data.sha256, false, '차단됨'));
        rowStatus(item, '민감정보 차단', 'FAIL');
        return { ok: false, blocked: true, detected: data.detected || [] };
      }
      rowStatus(item, '실패', 'FAIL');
      return { ok: false, error: data.error || `HTTP ${res.status}` };
    } catch (_) {
      rowStatus(item, '네트워크 오류', 'FAIL');
      return { ok: false, error: 'network' };
    }
  }

  async function upload() {
    if (!queue.length || uploading) return;
    const unmapped = queue.filter(it => !it.selected.size);
    if (unmapped.length) {
      setStatus(`${unmapped.length}개 파일에 통제 항목이 지정되지 않았습니다 — 추천 칩을 토글하거나 목록에서 추가하세요.`, 'error');
      return;
    }
    uploading = true;
    refreshBtn();
    let done = 0, blocked = 0, failed = 0;
    for (const item of queue) {
      const r = await uploadOne(item);
      if (r.ok) done++;
      else if (r.blocked) blocked++;
      else failed++;
    }
    const parts = [];
    if (done) parts.push(`<strong>${done}개 등록 완료</strong> — 증적 원장에 해시체인으로 기록됨`);
    if (blocked) parts.push(`${blocked}개 민감정보 검출로 차단 (저장되지 않음, 차단 사실만 원장 기록)`);
    if (failed) parts.push(`${failed}개 실패`);
    setStatus(parts.join('<br>'), failed ? 'error' : 'ok');
    queue = queue.filter(it => it.statusEl && !['완료 ✓'].includes(it.statusEl.textContent));
    uploading = false;
    renderQueue();
    refreshBtn();
  }

  btn.addEventListener('click', upload);
})();
