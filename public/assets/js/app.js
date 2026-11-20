// Small progressive enhancements. Every rule shown here is enforced again on
// the server; the application works with JavaScript disabled.
(function () {
  'use strict';

  // 1. Ask before an irreversible action (final submit, decision, delete).
  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-confirm]');
    if (button && !window.confirm(button.getAttribute('data-confirm'))) {
      event.preventDefault();
    }
  });

  // 2. Officer decision screen: preview the award and the resulting balance.
  var form = document.getElementById('decision-form');
  var balance = document.getElementById('resulting-balance');
  if (!form || !balance) { return; }
  var amountInput = document.getElementById('awarded_amount');
  var proposed = document.getElementById('proposed-award');
  var note = document.getElementById('balance-note');
  var baseNote = note.textContent;

  // Money is handled as integer cents, never as floating point.
  function toCents(text) {
    var m = /^(\d{1,12})(?:\.(\d{1,2}))?$/.exec(String(text).replace(/[\s,]/g, ''));
    return m ? parseInt(m[1], 10) * 100 + parseInt(((m[2] || '') + '00').slice(0, 2), 10) : null;
  }
  function format(cents) {
    var sign = cents < 0 ? '-' : '';
    var abs = Math.abs(cents);
    var whole = String(Math.floor(abs / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    return sign + whole + '.' + ('0' + (abs % 100)).slice(-2);
  }
  var available = toCents(balance.getAttribute('data-available'));
  var requested = toCents(balance.getAttribute('data-requested'));

  function refresh() {
    var outcome = (form.querySelector('input[name="outcome"]:checked') || {}).value;
    var declined = outcome === 'declined';
    amountInput.disabled = declined;
    var award = declined ? 0 : toCents(amountInput.value);
    balance.classList.remove('over');
    if (award === null || (!declined && amountInput.value.trim() === '')) {
      proposed.textContent = '—';
      balance.textContent = '—';
      note.textContent = baseNote;
      return;
    }
    proposed.textContent = format(award);
    balance.textContent = format(available - award);
    if (award > available) {
      balance.classList.add('over');
      note.textContent = 'This award exceeds the funds available in the call and will be refused.';
    } else if (award > requested) {
      note.textContent = 'This award exceeds the requested amount and will be refused.';
    } else {
      note.textContent = baseNote;
    }
  }
  form.addEventListener('input', refresh);
  form.addEventListener('change', refresh);
  refresh();
})();
