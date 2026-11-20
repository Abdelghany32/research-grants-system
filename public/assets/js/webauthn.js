// Security keys (WebAuthn): turns the server's JSON options into browser calls and back. The server verifies everything;
// this file only moves bytes between the browser's authenticator API and two POST endpoints.
(function () {
  'use strict';
  if (!window.PublicKeyCredential || !navigator.credentials) {
    var un = document.getElementById('wa-unsupported');
    if (un) { un.hidden = false; }
    return;
  }
  function b64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) { s += '='; }
    var bin = atob(s), buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { buf[i] = bin.charCodeAt(i); }
    return buf.buffer;
  }
  function bufToB64u(buf) {
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function post(url, csrf, fields) {
    var body = new URLSearchParams(Object.assign({ _csrf: csrf }, fields));
    return fetch(url, { method: 'POST', body: body, credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); });
  }
  function fail(msg) {
    var box = document.getElementById('wa-error');
    box.textContent = msg; box.hidden = false;
  }
  function descriptors(list) { return (list || []).map(function (d) { return { type: d.type, id: b64uToBuf(d.id) }; }); }

  var login = document.getElementById('wa-login');
  if (login) {
    login.hidden = false;
    document.getElementById('wa-go').addEventListener('click', function () {
      var csrf = login.getAttribute('data-csrf');
      post('/login/webauthn/options', csrf, {}).then(function (r) {
        if (!r.ok) { throw new Error(r.error); }
        var o = r.options;
        return navigator.credentials.get({ publicKey: {
          challenge: b64uToBuf(o.challenge), rpId: o.rpId, timeout: o.timeout, userVerification: o.userVerification,
          allowCredentials: descriptors(o.allowCredentials) } });
      }).then(function (cred) {
        var res = cred.response;
        return post('/login/webauthn/verify', csrf, { credential: JSON.stringify({ id: cred.id, response: {
          clientDataJSON: bufToB64u(res.clientDataJSON), authenticatorData: bufToB64u(res.authenticatorData), signature: bufToB64u(res.signature) } }) });
      }).then(function (r) {
        if (!r.ok) { throw new Error(r.error); }
        window.location.href = r.redirect;
      }).catch(function (e) { fail(e && e.message && e.message.length < 120 ? e.message : 'The security key was not accepted.'); });
    });
  }

  var reg = document.getElementById('wa-register');
  if (reg) {
    reg.hidden = false;
    document.getElementById('wa-add').addEventListener('click', function () {
      var csrf = reg.getAttribute('data-csrf');
      post('/account/security/webauthn/options', csrf, {}).then(function (r) {
        if (!r.ok) { throw new Error(r.error); }
        var o = r.options;
        return navigator.credentials.create({ publicKey: {
          challenge: b64uToBuf(o.challenge), rp: o.rp, timeout: o.timeout, attestation: o.attestation, pubKeyCredParams: o.pubKeyCredParams,
          authenticatorSelection: o.authenticatorSelection,
          user: { id: b64uToBuf(o.user.id), name: o.user.name, displayName: o.user.displayName },
          excludeCredentials: descriptors(o.excludeCredentials) } });
      }).then(function (cred) {
        var res = cred.response;
        return post('/account/security/webauthn/register', csrf, { name: document.getElementById('wa-name').value, credential: JSON.stringify({
          id: cred.id, response: { clientDataJSON: bufToB64u(res.clientDataJSON), attestationObject: bufToB64u(res.attestationObject) } }) });
      }).then(function (r) {
        if (!r.ok) { throw new Error(r.error); }
        window.location.href = r.redirect;
      }).catch(function (e) { fail(e && e.message && e.message.length < 120 ? e.message : 'The key could not be registered.'); });
    });
  }
})();
