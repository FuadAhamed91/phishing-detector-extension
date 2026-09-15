/**
 * Phishing Link Detector - content script.
 *
 * Watches every <a> on the page through event delegation, waits until the
 * cursor has rested on a link for HOVER_DELAY_MS, asks the background service
 * worker to score the link, and renders the verdict as a floating badge next
 * to the cursor. Everything is torn down again on mouseout.
 */
(() => {
  'use strict';

  const HOVER_DELAY_MS = 400;  // debounce before a hover turns into a request
  const CURSOR_OFFSET_X = 14;  // gap between the cursor and the tooltip
  const CURSOR_OFFSET_Y = 18;
  const VIEWPORT_MARGIN = 8;   // keep the tooltip at least this far from the edges
  const MESSAGE_TYPE = 'ANALYZE_URL';

  // document.body is null for XML/SVG documents; fall back to the root element.
  const root = document.body || document.documentElement;
  if (!root) return;

  let activeLink = null;   // <a> currently under the cursor (if scoreable)
  let hoverTimer = null;   // pending debounce timer
  let requestId = 0;       // lets late responses for an old link be ignored
  let tooltip = null;      // { el, label, score, width, height }
  const cursor = { x: 0, y: 0 };

  /* ---------- link filtering ---------- */

  /**
   * Returns an absolute http(s) URL for the anchor, or null when the link is
   * not worth scoring (empty, in-page "#" anchor, javascript:, mailto:, ...).
   */
  function getScoreableUrl(anchor) {
    const raw = (anchor.getAttribute('href') || '').trim();
    if (raw === '' || raw.startsWith('#')) return null;
    if (/^javascript:/i.test(raw)) return null; // covers javascript:void(0)

    let url;
    try {
      url = new URL(raw, document.baseURI); // resolves relative hrefs, honours <base>
    } catch {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url.href;
  }

  /* ---------- tooltip DOM ---------- */

  function createTooltip() {
    const el = document.createElement('div');
    el.className = 'phishing-tooltip';

    const label = document.createElement('span');
    label.className = 'phishing-tooltip__label';

    const score = document.createElement('span');
    score.className = 'phishing-tooltip__score';

    el.append(label, score);
    root.appendChild(el);
    return { el, label, score, width: 0, height: 0 };
  }

  function positionTooltip() {
    if (!tooltip) return;
    const { width, height } = tooltip;
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    // Prefer below-right of the cursor; flip when that would leave the viewport.
    let x = cursor.x + CURSOR_OFFSET_X;
    let y = cursor.y + CURSOR_OFFSET_Y;
    if (x + width + VIEWPORT_MARGIN > vw) x = cursor.x - width - CURSOR_OFFSET_X;
    if (y + height + VIEWPORT_MARGIN > vh) y = cursor.y - height - CURSOR_OFFSET_Y;

    x = Math.min(Math.max(x, VIEWPORT_MARGIN), vw - width - VIEWPORT_MARGIN);
    y = Math.min(Math.max(y, VIEWPORT_MARGIN), vh - height - VIEWPORT_MARGIN);

    tooltip.el.style.left = `${Math.round(x)}px`;
    tooltip.el.style.top = `${Math.round(y)}px`;
  }

  function showTooltip({ score, status }) {
    if (!tooltip || !tooltip.el.isConnected) tooltip = createTooltip();
    const { el, label } = tooltip;
    const isSafe = status === 'safe';

    el.classList.toggle('safe', isSafe);
    el.classList.toggle('warning', !isSafe);
    label.textContent = isSafe ? 'Safe link' : 'Suspicious link';
    tooltip.score.textContent = `${score}%`;

    // Measure once per render; mousemove repositions without re-measuring.
    tooltip.width = el.offsetWidth;
    tooltip.height = el.offsetHeight;
    positionTooltip();

    // Reading offsetWidth above forced a style flush while opacity was 0, so
    // adding the class now actually animates instead of snapping.
    el.classList.add('visible');
  }

  function removeTooltip() {
    if (!tooltip) return;
    tooltip.el.remove();
    tooltip = null;
  }

  /* ---------- background messaging ---------- */

  function requestAnalysis(anchor, url) {
    const id = ++requestId;
    const onResponse = (response) => {
      if (chrome.runtime.lastError) return;                  // worker unavailable
      if (id !== requestId || anchor !== activeLink) return; // cursor has moved on
      if (!response || typeof response.score !== 'number') return;
      showTooltip(response);
    };
    try {
      chrome.runtime.sendMessage({ type: MESSAGE_TYPE, url }, onResponse);
    } catch {
      // Extension was reloaded/removed while this page stayed open; ignore.
    }
  }

  /* ---------- hover lifecycle ---------- */

  function clearHover() {
    if (hoverTimer !== null) {
      clearTimeout(hoverTimer);
      hoverTimer = null;
    }
    activeLink = null;
    removeTooltip();
  }

  function onMouseOver(event) {
    const target = event.target;
    if (!(target instanceof Element)) return;

    const anchor = target.closest('a[href]');
    if (anchor === activeLink) return; // moving between children of the same link

    clearHover();
    if (!anchor) return;

    const url = getScoreableUrl(anchor);
    if (!url) return;

    activeLink = anchor;
    cursor.x = event.clientX;
    cursor.y = event.clientY;
    hoverTimer = setTimeout(() => {
      hoverTimer = null;
      requestAnalysis(anchor, url);
    }, HOVER_DELAY_MS);
  }

  function onMouseOut(event) {
    if (!activeLink) return;
    const next = event.relatedTarget;
    if (next instanceof Node && activeLink.contains(next)) return; // still inside the link
    clearHover();
  }

  // Keeps the badge glued to the cursor while it travels along a long link.
  function onMouseMove(event) {
    if (!activeLink) return;
    cursor.x = event.clientX;
    cursor.y = event.clientY;
    if (tooltip) positionTooltip();
  }

  root.addEventListener('mouseover', onMouseOver);
  root.addEventListener('mouseout', onMouseOut);
  root.addEventListener('mousemove', onMouseMove, { passive: true });
})();
