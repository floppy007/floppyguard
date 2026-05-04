# Live 2.14.0 Gap Check

Date: 2026-04-15

This note records the current delta between the FloppyGuard fork in this repo and the live Nginx Proxy Manager instance running on the same host.

## Live Reference

- Container: `npm-app-1`
- Image: `jc21/nginx-proxy-manager:latest`
- Build version: `2.14.0`
- Build commit: `84fb2729`
- Build date: `2026-02-17 05:42:59 UTC`

## Conclusion

This fork is not just a relabeled copy of live `2.14.0`.

The current codebase is best described as:

- a close `2.14.0`-era base
- plus deliberate FloppyGuard extensions
- plus some dependency drift beyond the live image

That means the current `2.14.0` label in the preview is directionally correct for the product line, but it does not mean this repo is byte-identical to the live upstream build.

## Confirmed Intentional Deltas

These differences appear to be product or preview specific and should not be treated as accidental drift:

- `backend/routes/main.js`
  - mounts `wireguard`
  - accepts both `""` and `"/"` on the health route
- `backend/app.js`
  - custom route mounting structure
  - extra API surface for FloppyGuard features
- `backend/index.js`
  - reads `PORT` from env instead of assuming `3000`
- `backend/internal/certificate.js`
  - supports `NPM_LETSENCRYPT_ROOT`
  - supports `NPM_CUSTOM_SSL_ROOT`
  - needed for local preview against imported live cert paths
- `backend/setup.js`
  - supports `SKIP_CERTBOT_PLUGIN_SETUP=true`
  - needed so preview startup does not fail on missing certbot plugin bootstrap
- `backend/internal/token.js`
  - local bugfix applied for refresh-token error handling
- `backend/internal/wireguard.js`
  - FloppyGuard-specific backend feature
- `backend/routes/wireguard.js`
  - FloppyGuard-specific backend route

## Confirmed Upstream Matches

Some core files still match the live container exactly:

- `backend/routes/version.js`
- `backend/lib/certbot.js`

This supports the conclusion that the fork is still based on the same upstream generation, not a completely separate codebase.

## Confirmed Drift Beyond Branding

The repo also differs from live in ways that are not just branding or platform routing:

- `backend/package.json`
  - dependency versions differ from the live container
  - example packages with higher local versions:
    - `@apidevtools/json-schema-ref-parser`
    - `compression`
    - `mysql2`
    - `pg`
    - `temp-write`
  - extra script present locally:
    - `regenerate-config`
- frontend has also been intentionally redesigned and rebranded for FloppyGuard

This means we should not describe the fork as "the exact live 2.14.0 code" without qualification.

## Practical Recommendation

Use this repo as:

- `FloppyGuard Platform based on NPM 2.14.0`

Do not treat it as:

- `an untouched mirror of live jc21/nginx-proxy-manager 2.14.0`

## Next Safe Sync Strategy

If we want to reduce drift without losing FloppyGuard features, do it selectively:

1. Compare live `2.14.0` backend files and keep only deliberate FloppyGuard deltas.
2. Sync unmodified upstream files back to the live `2.14.0` versions where safe.
3. Keep preview-only changes isolated behind env flags.
4. Treat frontend branding/layout work as product-owned, not upstream drift.

## Command References

Useful commands used during this check:

- `docker exec npm-app-1 sh -lc 'printf "version=%s\ncommit=%s\ndate=%s\n" "$NPM_BUILD_VERSION" "$NPM_BUILD_COMMIT" "$NPM_BUILD_DATE"'`
- `diff -u <(docker exec npm-app-1 sh -lc 'cd /app && sed -n "1,220p" package.json') backend/package.json`
- `diff -u <(docker exec npm-app-1 sh -lc 'cd /app && sed -n "1,260p" routes/main.js') backend/routes/main.js`
- `diff -u <(docker exec npm-app-1 sh -lc 'cd /app && sed -n "1,260p" setup.js') backend/setup.js`
