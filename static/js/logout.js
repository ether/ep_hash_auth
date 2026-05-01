'use strict';

// Logging out of HTTP Basic auth requires evicting the browser's cached
// `Authorization` header. Server-side session destruction is not enough —
// the browser would just re-authenticate on the next request.
//
// The cross-browser dance:
//   1. Send a fetch to /ep_hash_auth/logout with a deliberately invalid
//      Authorization header. Chrome treats the new (failing) credentials as
//      replacing the cached good ones for this origin.
//   2. The server returns 401 with a per-request realm, which nudges
//      Firefox/Safari to drop their cred cache for the original realm.
//   3. Redirect to "/" so the user lands somewhere sensible. The next
//      request to a protected resource will trigger a fresh Basic prompt.

(() => {
  const LOGOUT_PATH = '/ep_hash_auth/logout';

  const doLogout = () => {
    const poison = fetch(LOGOUT_PATH, {
      method: 'GET',
      credentials: 'include',
      headers: {Authorization: `Basic ${btoa('logout:logout')}`},
      cache: 'no-store',
    }).catch(() => { /* network failures still drop us at "/" below */ });

    poison.finally(() => {
      window.location.href = '/';
    });
  };

  const bind = () => {
    const btn = document.getElementById('ep_hash_auth_logout_btn');
    if (!btn || btn.dataset.epHashAuthBound === '1') return;
    btn.dataset.epHashAuthBound = '1';
    btn.addEventListener('click', (ev) => {
      ev.preventDefault();
      doLogout();
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();
