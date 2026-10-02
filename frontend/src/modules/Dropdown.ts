/**
 * Bootstrap reads `data-bs-popper-config` as JSON. A fixed Popper strategy
 * lets dropdown menus escape `overflow: hidden/auto` ancestors such as cards
 * and `.table-responsive`, which otherwise clip menus in the last table rows.
 */
export const POPPER_FIXED = JSON.stringify({ strategy: "fixed" });
