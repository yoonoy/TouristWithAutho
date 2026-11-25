// Visitor accounts: sign in, register, confirm e-mail, reset password.
// Talks to /api/auth/* (see auth.js on the server). Text comes from translations.js (keys starting with "auth").
(() => {
  const dialog = document.querySelector('#auth-dialog');
  const openButton = document.querySelector('#auth-open');
  if (!dialog || !openButton || window.location.protocol === 'file:') return;

  const titleEl = document.querySelector('#auth-title');
  const kickerEl = document.querySelector('#auth-kicker');
  const statusEl = document.querySelector('#auth-status');
  const closeButton = document.querySelector('#auth-close');
  const resendButton = document.querySelector('#auth-resend');
  const views = [...dialog.querySelectorAll('[data-auth-view]')];
  const forms = {
    login: document.querySelector('#auth-login-form'),
    register: document.querySelector('#auth-register-form'),
    verify: document.querySelector('#auth-verify-form'),
    forgot: document.querySelector('#auth-forgot-form'),
    reset: document.querySelector('#auth-reset-form'),
    change: document.querySelector('#auth-change-form')
  };
  const headings = {
    login: ['authKickerLogin', 'authTitleLogin'],
    register: ['authKickerRegister', 'authTitleRegister'],
    verify: ['authKickerVerify', 'authTitleVerify'],
    forgot: ['authKickerForgot', 'authTitleForgot'],
    reset: ['authKickerReset', 'authTitleReset'],
    account: ['authKickerAccount', 'authTitleAccount']
  };
  const RESEND_SECONDS = 60;

  const state = { user: null, view: 'login', email: '', status: null, resendUntil: 0, closeTimer: 0, resendTimer: 0 };

  /* ---------- helpers ---------- */

  function t(key, vars = {}) {
    const translations = window.siteTranslations || {};
    const ui = (translations[document.documentElement.lang] || translations.en || { ui: {} }).ui;
    const text = ui[key] ?? translations.en?.ui?.[key] ?? key;
    return text.replace(/\{(\w+)\}/g, (_, name) => vars[name] ?? '');
  }

  async function api(name, body) {
    const options = { credentials: 'same-origin' };
    if (body !== undefined) {
      options.method = 'POST';
      options.headers = { 'Content-Type': 'application/json' };
      options.body = JSON.stringify({ ...body, locale: document.documentElement.lang });
    }
    let response;
    try {
      response = await fetch(`/api/auth/${name}`, options);
    } catch {
      throw Object.assign(new Error('network'), { code: 'network' });
    }
    let data = {};
    try {
      data = await response.json();
    } catch {
      // Non-JSON answer: handled below as a generic error.
    }
    if (!response.ok) throw Object.assign(new Error(data.error || 'error'), { code: data.code, data, status: response.status });
    return data;
  }

  function setStatus(kind, key, vars) {
    state.status = key ? { kind, key, vars } : null;
    renderStatus();
  }

  function setError(error) {
    const key = `authErr_${error.code}`;
    const known = error.code && window.siteTranslations?.en?.ui?.[key];
    setStatus('error', known ? key : 'authErr_generic');
  }

  function renderStatus() {
    statusEl.textContent = state.status ? t(state.status.key, state.status.vars) : '';
    statusEl.dataset.state = state.status?.kind || '';
  }

  function busy(form, isBusy) {
    form.querySelectorAll('button[type="submit"]').forEach((button) => { button.disabled = isBusy; });
  }

  function formValues(form) {
    return Object.fromEntries(new FormData(form));
  }

  /* ---------- views ---------- */

  function renderTexts() {
    const [kicker, title] = headings[state.view];
    kickerEl.textContent = t(kicker);
    titleEl.textContent = t(title);
    closeButton.setAttribute('aria-label', t('authClose'));
    document.querySelector('#auth-verify-note').textContent = t('authCodeSent', { email: state.email });
    document.querySelector('#auth-reset-note').textContent = t('authResetNote', { email: state.email });
    document.querySelector('#auth-account-note').textContent = t('authSignedInAs', { email: state.user?.email || '' });
    renderStatus();
    renderResend();
  }

  function setView(view, { keepStatus = false } = {}) {
    window.clearTimeout(state.closeTimer);
    state.view = view;
    views.forEach((element) => { element.hidden = element.dataset.authView !== view; });
    if (!keepStatus) setStatus('', null);
    renderTexts();
    const firstField = views.find((element) => element.dataset.authView === view)?.querySelector('input:not(.consultation-trap)');
    if (dialog.open && firstField) window.setTimeout(() => firstField.focus(), 30);
  }

  function openDialog(view) {
    const navigation = document.querySelector('.main-nav');
    const toggle = document.querySelector('.menu-toggle');
    navigation?.classList.remove('is-open');
    toggle?.setAttribute('aria-expanded', 'false');
    if (!dialog.open) dialog.showModal();
    setView(view);
  }

  function startResendCountdown() {
    state.resendUntil = Date.now() + RESEND_SECONDS * 1000;
    window.clearInterval(state.resendTimer);
    state.resendTimer = window.setInterval(() => {
      renderResend();
      if (Date.now() >= state.resendUntil) window.clearInterval(state.resendTimer);
    }, 1000);
    renderResend();
  }

  function renderResend() {
    if (!resendButton) return;
    const secondsLeft = Math.max(0, Math.ceil((state.resendUntil - Date.now()) / 1000));
    resendButton.disabled = secondsLeft > 0;
    resendButton.textContent = secondsLeft > 0 ? t('authResendIn', { s: secondsLeft }) : t('authResend');
  }

  /* ---------- signed-in state ---------- */

  function renderNav() {
    if (state.user) {
      openButton.textContent = state.user.firstName;
      openButton.title = state.user.email;
      openButton.classList.add('is-signed-in');
      openButton.setAttribute('aria-label', `${t('authTitleAccount')}: ${state.user.firstName}`);
    } else {
      openButton.textContent = t('authSignIn');
      openButton.removeAttribute('title');
      openButton.classList.remove('is-signed-in');
      openButton.removeAttribute('aria-label');
    }
  }

  function prefillConsultation() {
    const form = document.querySelector('#consultation-form');
    if (!state.user || !form) return;
    if (form.elements.name && !form.elements.name.value) form.elements.name.value = state.user.firstName;
    if (form.elements.surname && !form.elements.surname.value) form.elements.surname.value = state.user.lastName;
  }

  function signedIn(user, messageKey) {
    state.user = user;
    renderNav();
    prefillConsultation();
    Object.values(forms).forEach((form) => form.reset());
    setView('account', { keepStatus: true });
    setStatus('ok', messageKey, { name: user.firstName });
    state.closeTimer = window.setTimeout(() => { if (dialog.open && state.view === 'account') dialog.close(); }, 1600);
  }

  /* ---------- form handlers ---------- */

  function handle(form, action) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      busy(form, true);
      setStatus('', null);
      try {
        await action(formValues(form));
      } catch (error) {
        setError(error);
      } finally {
        busy(form, false);
      }
    });
  }

  handle(forms.login, async (values) => {
    try {
      const { user } = await api('login', { email: values.email, password: values.password });
      signedIn(user, 'authWelcome');
    } catch (error) {
      if (error.code === 'not_verified') {
        state.email = (values.email || '').trim().toLowerCase();
        forms.login.reset();
        setView('verify', { keepStatus: true });
        setStatus('error', 'authErr_not_verified');
        startResendCountdown();
        return;
      }
      throw error;
    }
  });

  handle(forms.register, async (values) => {
    const data = await api('register', {
      firstName: values.firstName,
      lastName: values.lastName,
      email: values.email,
      password: values.password,
      website: values.website
    });
    state.email = data.email || (values.email || '').trim().toLowerCase();
    forms.register.reset();
    setView('verify');
    startResendCountdown();
  });

  handle(forms.verify, async (values) => {
    const { user } = await api('verify-email', { email: state.email, code: values.code });
    signedIn(user, 'authVerified');
  });

  handle(forms.forgot, async (values) => {
    await api('forgot-password', { email: values.email });
    state.email = (values.email || '').trim().toLowerCase();
    forms.forgot.reset();
    setView('reset');
    setStatus('ok', 'authResetSent');
  });

  handle(forms.reset, async (values) => {
    await api('reset-password', { email: state.email, code: values.code, password: values.password });
    forms.reset.reset();
    setView('login');
    forms.login.elements.email.value = state.email;
    setStatus('ok', 'authResetDone');
    forms.login.elements.password.focus();
  });

  handle(forms.change, async (values) => {
    await api('change-password', { currentPassword: values.currentPassword, newPassword: values.newPassword });
    forms.change.reset();
    setStatus('ok', 'authPasswordChanged');
  });

  resendButton.addEventListener('click', async () => {
    resendButton.disabled = true;
    try {
      await api('resend-code', { email: state.email, purpose: 'verify' });
      setStatus('ok', 'authCodeResent');
    } catch (error) {
      setError(error);
    }
    startResendCountdown();
  });

  document.querySelector('#auth-signout').addEventListener('click', async () => {
    try {
      await api('logout', {});
    } catch (error) {
      setError(error);
      return;
    }
    state.user = null;
    renderNav();
    setView('login');
    setStatus('ok', 'authSignedOut');
  });

  /* ---------- dialog wiring ---------- */

  dialog.querySelectorAll('[data-auth-go]').forEach((button) => {
    button.addEventListener('click', () => setView(button.dataset.authGo));
  });

  openButton.addEventListener('click', () => {
    const pending = ['verify', 'reset'].includes(state.view) && !state.user ? state.view : 'login';
    openDialog(state.user ? 'account' : pending);
  });

  closeButton.addEventListener('click', () => dialog.close());

  dialog.addEventListener('click', (event) => {
    if (event.target !== dialog) return;
    const box = dialog.getBoundingClientRect();
    const inside = event.clientX >= box.left && event.clientX <= box.right && event.clientY >= box.top && event.clientY <= box.bottom;
    if (!inside) dialog.close();
  });

  dialog.addEventListener('close', () => {
    window.clearTimeout(state.closeTimer);
    forms.login.reset();
    forms.register.reset();
    forms.change.reset();
    forms.reset.reset();
  });

  // Re-render translated text whenever the site language changes (script.js sets <html lang>).
  new MutationObserver(() => {
    renderNav();
    renderTexts();
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] });

  /* ---------- start ---------- */

  renderNav();
  renderTexts();
  api('me').then(({ user }) => {
    if (!user) return;
    state.user = user;
    renderNav();
    prefillConsultation();
  }).catch(() => {
    // Server offline: the site stays usable without an account.
  });
})();
