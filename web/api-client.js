/*
 * Shared fetch wrapper for the dashboard.
 * - Sends X-API-Key when one has been entered (needed once the server sets VERITAS_API_KEY).
 * - On a 401 it asks for the key once, remembers it for this browser tab only (sessionStorage),
 *   and retries the request.
 * Loaded before app.js so every existing fetch() call goes through it unchanged.
 */
(function () {
  const KEY = 'veritasApiKey';
  const nativeFetch = window.fetch.bind(window);
  const read = () => { try { return sessionStorage.getItem(KEY) || ''; } catch (e) { return ''; } };
  const write = (v) => { try { sessionStorage.setItem(KEY, v); } catch (e) { /* private mode */ } };
  const sameOrigin = (url) => typeof url === 'string' && (url.startsWith('/') || url.startsWith(location.origin));

  function withKey(init, key) {
    const headers = new Headers((init && init.headers) || {});
    if (key) headers.set('X-API-Key', key);
    return Object.assign({}, init, { headers });
  }

  window.fetch = async function (url, init) {
    if (!sameOrigin(url)) return nativeFetch(url, init);
    let res = await nativeFetch(url, withKey(init, read()));
    if (res.status === 401) {
      const entered = window.prompt('This Veritas server requires an API key:');
      if (entered) {
        write(entered.trim());
        res = await nativeFetch(url, withKey(init, entered.trim()));
      }
    }
    return res;
  };
})();
