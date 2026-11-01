let regionNames: Intl.DisplayNames | null = null;

export const countryName = (code: string) => {
	if (code === "ZZ") return "Unbekannt";
	try {
		regionNames ??= new Intl.DisplayNames([document.documentElement.lang || navigator.language || "de", "en"], {
			type: "region",
		});
		return regionNames.of(code) || code;
	} catch {
		return code;
	}
};

export const norm = (list: string[]) => [...new Set(list)].sort();

export const sameList = (a: string[], b: string[]) => {
	const x = norm(a);
	const y = norm(b);
	return x.length === y.length && x.every((v, i) => v === y[i]);
};
