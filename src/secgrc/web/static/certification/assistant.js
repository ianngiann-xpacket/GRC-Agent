/* AI 심사지원 에이전트 — advisory 전용 채팅.
 * 결정론적 백엔드 응답(/api/audit/assistant)만 렌더링.
 * 공식 판정·증적 승인·결함 종결은 절대 수행하지 않음을 항상 표기.
 * 서버 응답·사용자 입력 모두 AS.esc() 후 제한적 마크다운 변환.
 */
class AuditAssistant {
  constructor(bodyId, suggId, inputId, sendId) {
    this.body = document.getElementById(bodyId);
    this.sugg = document.getElementById(suggId);
    this.input = inputId ? document.getElementById(inputId) : null;
    this.send = sendId ? document.getElementById(sendId) : null;
    this.busy = false;
  }

  init() {
    this.appendMsg('bot',
      '안녕하세요! ISMS-P 인증심사를 위한 AI 심사지원 에이전트입니다.<br><br>' +
      '현재 심사에서 가장 먼저 확인해야 할 항목은 <strong>퇴직자 계정 관리(2.2.5)</strong>입니다.');
    this.renderSuggests(['네, 확인해 주세요', '다른 항목도 볼 수 있나요?', '현재 준비도는?']);
    if (this.input && this.send) {
      this.send.addEventListener('click', () => this.submitInput());
      this.input.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.submitInput(); }
      });
    }
    return Promise.resolve();
  }

  /* AS.esc() 적용 후의 문자열에만 사용 — 제한적 마크다운 */
  mdLite(escaped) {
    return escaped
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/^- /gm, '• ')
      .replace(/\n/g, '<br>');
  }

  appendMsg(role, html) {
    const el = document.createElement('div');
    el.className = `amsg ${role}`;
    el.innerHTML = html;
    this.body.appendChild(el);
    this.body.scrollTop = this.body.scrollHeight;
    return el;
  }

  submitInput() {
    if (!this.input || this.busy) return;
    const text = this.input.value.trim();
    if (!text) return;
    this.input.value = '';
    this.ask(text);
  }

  renderSuggests(list) {
    this.sugg.innerHTML = list.map(t =>
      `<button class="sugg-btn">${AS.esc(t)}</button>`).join('');
    this.sugg.querySelectorAll('.sugg-btn').forEach(b =>
      b.addEventListener('click', () => this.ask(b.textContent)));
  }

  setBusy(on) {
    this.busy = on;
    if (this.send) this.send.disabled = on;
    if (this.input) this.input.disabled = on;
  }

  async ask(text) {
    if (this.busy) return;
    this.setBusy(true);
    this.appendMsg('user', AS.esc(text).replace(/\n/g, '<br>'));
    const pend = this.appendMsg('bot pending', '<em>분석 중…</em>');
    try {
      const res = await AS.api('/api/audit/assistant', {
        method: 'POST',
        body: JSON.stringify({ message: text, page: this.page || undefined }),
      });
      let html = this.mdLite(AS.esc(res.reply || ''));
      // 생성 출처 배지 — LLM 실호출 vs 규칙 기반을 사용자에게 명시
      const gen = res.generated_by === 'llm' ? 'llm' : 'rule';
      html = `<span class="agen-badge ${gen}">${gen === 'llm' ? 'LLM 응답' : '규칙 기반'}</span>` + html;
      const links = (res.links || []).filter(l => typeof l.href === 'string' && l.href.startsWith('/'));
      if (links.length) {
        html += '<div class="amsg-links">' + links.map(l =>
          `<a href="${AS.url(l.href)}" class="rbtn" style="font-size:11px;padding:5px 10px">${AS.esc(l.label)} →</a>`
        ).join('') + '</div>';
      }
      pend.classList.remove('pending');
      pend.innerHTML = html;
      if (res.disclaimer) {
        const d = this.body.parentElement.querySelector('.advisory');
        if (d) d.textContent = 'ⓘ ' + res.disclaimer;
      }
      this.renderSuggests(res.suggestions || []);
    } catch (e) {
      pend.innerHTML = '응답을 가져오지 못했습니다. 잠시 후 다시 시도해 주세요.';
    } finally {
      this.setBusy(false);
      if (this.input) this.input.focus();
      this.body.scrollTop = this.body.scrollHeight;
    }
  }
}

/* 전 페이지 공통 — base.html의 플로팅 드로어 자동 초기화 */
document.addEventListener('DOMContentLoaded', () => {
  const drawer = document.getElementById('assistantDrawer');
  if (!drawer || !document.getElementById('assistantBody')) return;
  const ast = new AuditAssistant('assistantBody', 'assistantSugg', 'assistantInput', 'assistantSend');
  ast.page = drawer.dataset.page || '';
  ast.init();
  const fab = document.getElementById('assistantFab');
  if (fab) fab.addEventListener('click', () => drawer.classList.toggle('open'));
  const close = document.getElementById('assistantClose');
  if (close) close.addEventListener('click', () => drawer.classList.remove('open'));
});
