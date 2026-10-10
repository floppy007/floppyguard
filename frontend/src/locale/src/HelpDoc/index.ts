// Only the languages selectable in IntlProvider (localeOptions) are bundled:
// every .md is inlined as a data URI into the entry chunk, so unreachable
// languages only cost download size. Others fall back to English below.
import * as de from "./de/index";
import * as en from "./en/index";
import * as fr from "./fr/index";

const items: any = { en, de, fr };

const fallbackLang = "en";

export const getHelpFile = (lang: string, section: string): string => {
	if (typeof items[lang] !== "undefined" && typeof items[lang][section] !== "undefined") {
		return items[lang][section].default;
	}
	// Fallback to English
	if (typeof items[fallbackLang] !== "undefined" && typeof items[fallbackLang][section] !== "undefined") {
		return items[fallbackLang][section].default;
	}
	throw new Error(`Cannot load help doc for ${lang}-${section}`);
};

export default items;
