// Character class shared by every URL that ends up in a root-sourced shell file
// (agent config.env written via sed/bash, see internal/agent.js sanitizeHubUrl)
// or verbatim in the nginx config (`return 301 {{ meta.redirect }}`, see
// internal/setting.js). One source of truth: tightening it here tightens the
// route schema and the persistence gate together.
// The JSON schema (schema/paths/settings/settingID/put.json) cannot import this,
// so internal/safe-url.test.js asserts it stays equal to SAFE_HTTP_URL_PATTERN.
export const URL_SAFE_CHAR_CLASS = "[^\\s\"'$`\\\\;|&(){}<>!#]";
export const SAFE_HTTP_URL_PATTERN = `^https?://${URL_SAFE_CHAR_CLASS}+$`;
export const SAFE_HTTPS_URL_PATTERN = `^https://${URL_SAFE_CHAR_CLASS}+$`;
export const SAFE_HTTP_URL_REGEX = new RegExp(SAFE_HTTP_URL_PATTERN);
// "every character is safe" — protocol is checked separately by the caller.
export const URL_SAFE_CHARS_REGEX = new RegExp(`^${URL_SAFE_CHAR_CLASS}+$`);
