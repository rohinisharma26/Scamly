// Scamly accounts + history (Supabase). Loaded after the main page script.
(function () {
  // 1. Paste your two values from Supabase: Project Settings -> API
  const SUPABASE_URL = 'https://wlowpxhjzjhmcohnkbuy.supabase.co';
  const SUPABASE_KEY = 'sb_publishable_xbFEkhZ9XyGg58B75Dmvsg_u7MyJG0u'; // publishable / anon key only, never the secret key

  const configured = !SUPABASE_URL.includes('YOUR-PROJECT') && !SUPABASE_KEY.includes('YOUR-PUBLISHABLE');
  const sb = configured && window.supabase ? window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY) : null;

  let currentUser = null;
  let lastResult = window.scamlyLastResult || null;

  const TYPE_LABELS = {
    urgency: 'Artificial urgency',
    verification_pressure: 'Pressure to verify details',
    reward: 'Unsolicited reward',
    payment_request: 'Payment request',
    authority_impersonation: 'Authority impersonation',
    job_offer: 'Unsolicited job offer',
    delivery_fee: 'Delivery problem or fee',
    threat: 'Threat of consequences',
    secrecy: 'Avoiding verification',
    suspicious_link: 'Suspicious link'
  };

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ---------- Modal helpers ----------
  const INPUT_CLASS = 'w-full mb-3 bg-[#05060a] text-white border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-cyan-500/50';
  const PRIMARY_BTN = 'px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-400 to-cyan-300 text-[#00363a] text-sm font-bold hover:brightness-110 transition-all disabled:opacity-50';
  const SECONDARY_BTN = 'px-4 py-2 rounded-lg bg-[#141722] border border-white/10 text-sm text-on-surface hover:text-white hover:border-white/20 transition-all';

  function closeModal() {
    const el = document.getElementById('scamlyModal');
    if (el) el.remove();
  }

  function openModal(innerHtml) {
    closeModal();
    const overlay = document.createElement('div');
    overlay.id = 'scamlyModal';
    overlay.className = 'fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4';
    overlay.innerHTML = '<div class="w-full max-w-md max-h-[85vh] overflow-y-auto bg-[#090b11] border border-white/10 rounded-2xl p-6 shadow-2xl text-on-surface">' + innerHtml + '</div>';
    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
    document.body.appendChild(overlay);
    return overlay;
  }
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  // ---------- Sign in / create account ----------
  function openAuth() {
    if (!sb) {
      const m = openModal(
        '<h3 class="text-lg font-semibold text-white mb-2">Accounts are not set up yet</h3>' +
        '<p class="text-sm text-on-surface-variant mb-4">Add your Supabase URL and key at the top of scamly-auth.js, then refresh.</p>' +
        '<button id="scClose" class="' + SECONDARY_BTN + '">Close</button>'
      );
      m.querySelector('#scClose').addEventListener('click', closeModal);
      return;
    }

    const m = openModal(
      '<h3 class="text-lg font-semibold text-white mb-1">Sign in to Scamly</h3>' +
      '<p class="text-sm text-on-surface-variant mb-4">Save your scans and revisit them later.</p>' +
      '<input id="scAuthEmail" type="email" placeholder="Email" class="' + INPUT_CLASS + '">' +
      '<input id="scAuthPass" type="password" placeholder="Password (at least 6 characters)" class="' + INPUT_CLASS + '">' +
      '<p id="scAuthMsg" class="text-xs min-h-[1rem] mb-3"></p>' +
      '<div class="flex gap-2">' +
      '<button id="scSignIn" class="flex-1 ' + PRIMARY_BTN + '">Sign in</button>' +
      '<button id="scSignUp" class="flex-1 ' + SECONDARY_BTN + '">Create account</button>' +
      '</div>'
    );

    const email = () => m.querySelector('#scAuthEmail').value.trim();
    const pass = () => m.querySelector('#scAuthPass').value;
    const msg = (text, ok) => {
      const el = m.querySelector('#scAuthMsg');
      el.textContent = text;
      el.className = 'text-xs min-h-[1rem] mb-3 ' + (ok ? 'text-cyan-300' : 'text-rose-300');
    };

    m.querySelector('#scSignIn').addEventListener('click', async () => {
      msg('Signing in…', true);
      const { error } = await sb.auth.signInWithPassword({ email: email(), password: pass() });
      if (error) msg(error.message, false); else closeModal();
    });

    m.querySelector('#scSignUp').addEventListener('click', async () => {
      msg('Creating account…', true);
      const { data, error } = await sb.auth.signUp({ email: email(), password: pass() });
      if (error) msg(error.message, false);
      else if (!data.session) msg('Check your email to confirm your account, then sign in.', true);
      else closeModal();
    });
  }

  // ---------- History ----------
  function renderRow(row) {
    const when = new Date(row.created_at).toLocaleString();
    const chips = (row.indicator_types || []).map((t) =>
      '<span class="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-[11px]">' + escapeHtml(TYPE_LABELS[t] || t) + '</span>'
    ).join(' ');
    const text = row.raw_text
      ? '<p class="mt-2 text-xs text-on-surface-variant whitespace-pre-wrap break-words">' + escapeHtml(row.raw_text) + '</p>'
      : '';
    return '<div data-row class="bg-[#05060a] border border-white/10 rounded-xl p-3">' +
      '<div class="flex items-start justify-between gap-2">' +
      '<div><div class="font-semibold text-white">' + escapeHtml(row.archetype || 'No known pattern') + '</div>' +
      '<div class="text-[11px] text-on-surface-variant">' + escapeHtml(when) + '</div></div>' +
      '<button data-del="' + escapeHtml(row.id) + '" class="text-xs text-rose-300 hover:text-rose-200">Delete</button>' +
      '</div>' +
      '<div class="flex flex-wrap gap-1.5 mt-2">' + chips + '</div>' + text + '</div>';
  }

  async function openHistory() {
    const m = openModal(
      '<div class="flex items-center justify-between mb-1">' +
      '<h3 class="text-lg font-semibold text-white">Your history</h3>' +
      '<button id="scSignOut" class="' + SECONDARY_BTN + '">Sign out</button></div>' +
      '<p class="text-xs text-on-surface-variant mb-4">' + escapeHtml(currentUser ? currentUser.email || '' : '') + '</p>' +
      '<div id="scHistoryList" class="space-y-3 text-sm text-on-surface-variant">Loading…</div>'
    );

    m.querySelector('#scSignOut').addEventListener('click', async () => {
      await sb.auth.signOut();
      closeModal();
    });

    const list = m.querySelector('#scHistoryList');
    const { data, error } = await sb.from('analyses').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) { list.textContent = 'Could not load history: ' + error.message; return; }
    if (!data.length) { list.textContent = 'Nothing saved yet. Analyze a message, then press "Save to history".'; return; }

    list.innerHTML = data.map(renderRow).join('');
    list.querySelectorAll('[data-del]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        btn.textContent = 'Deleting…';
        const res = await sb.from('analyses').delete().eq('id', btn.dataset.del);
        if (res.error) btn.textContent = 'Failed';
        else btn.closest('[data-row]').remove();
      });
    });
  }

  // ---------- Header link: Sign in / History ----------
  const navLink = document.querySelector('a[data-path="sign-in"]');
  if (navLink) {
    navLink.addEventListener('click', (e) => {
      e.preventDefault();
      if (currentUser) openHistory(); else openAuth();
    });
  }

  // ---------- Save bar under the results (opt-in, per scan) ----------
  const resultsArea = document.getElementById('resultsArea');
  const bar = document.createElement('div');
  bar.className = 'hidden mt-4 pt-3 border-t border-white/10 flex flex-wrap items-center gap-3';
  bar.innerHTML =
    '<button id="scSave" class="' + PRIMARY_BTN + '">Sign in to save</button>' +
    '<label class="flex items-center gap-2 text-xs text-on-surface-variant cursor-pointer">' +
    '<input id="scIncludeText" type="checkbox" class="rounded border-white/20 bg-[#05060a]">' +
    'Also save the message text (off by default)</label>' +
    '<span id="scSaveStatus" class="text-xs text-on-surface-variant"></span>';
  if (resultsArea) resultsArea.appendChild(bar);

  const saveBtn = bar.querySelector('#scSave');
  const saveStatus = bar.querySelector('#scSaveStatus');

  function refreshUi() {
    if (navLink) navLink.textContent = currentUser ? 'History' : 'Sign in';
    saveBtn.textContent = currentUser ? 'Save to history' : 'Sign in to save';
  }

  saveBtn.addEventListener('click', async () => {
    if (!sb || !currentUser) { openAuth(); return; }
    if (!lastResult) return;
    const types = Array.from(new Set(lastResult.annotations.map((a) => a.type)));
    const includeText = bar.querySelector('#scIncludeText').checked;
    saveStatus.textContent = 'Saving…';
    const { error } = await sb.from('analyses').insert({
      archetype: lastResult.archetype ? lastResult.archetype.name : null,
      indicator_types: types,
      raw_text: includeText ? lastResult.text : null
    });
    saveStatus.textContent = error ? 'Could not save: ' + error.message : 'Saved to your history.';
  });

  // Called by the main page script after every analysis
  window.onScamlyResult = function (data) {
    lastResult = data;
    saveStatus.textContent = '';
    bar.classList.remove('hidden');
    bar.classList.add('flex');
  };
  if (window.scamlyLastResult) window.onScamlyResult(window.scamlyLastResult);
  // Called by the main page script when the user presses Clear
  window.onScamlyClear = function () {
    lastResult = null;
    saveStatus.textContent = '';
    bar.classList.add('hidden');
    bar.classList.remove('flex');
  };
  // ---------- Auth state ----------
  refreshUi();
  if (sb) {
    sb.auth.getSession().then(({ data }) => {
      currentUser = data.session ? data.session.user : null;
      refreshUi();
    });
    sb.auth.onAuthStateChange((_event, session) => {
      currentUser = session ? session.user : null;
      refreshUi();
    });
  }
})();