/**
 * Phishing Link Detector - background service worker.
 *
 * Receives URLs from the content script and answers with the verdict from the
 * scoring engine in scoring.js. Nothing ever leaves the browser.
 */
import { analyzeUrl } from './scoring.js';

const MESSAGE_TYPE = 'ANALYZE_URL';

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== MESSAGE_TYPE) return;
  sendResponse(analyzeUrl(message.url));
  // The response was sent synchronously, so there is no need to return true.
});
