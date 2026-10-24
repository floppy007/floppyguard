// Import single flags only: the whole set (~250 SVG components, ~220 KB) would
// otherwise land in the entry chunk, which loads on every page.
import DE from "country-flag-icons/react/3x2/DE";
import FR from "country-flag-icons/react/3x2/FR";
import US from "country-flag-icons/react/3x2/US";

/** Flags of the bundled locales (see localeOptions / getFlagCodeForLocale). */
const FLAGS: Record<string, typeof DE> = { DE, FR, US };

interface FlagProps {
	className?: string;
	countryCode: string;
}
function Flag({ className, countryCode }: FlagProps) {
	countryCode = countryCode.toUpperCase();
	const FlagElement = FLAGS[countryCode];
	if (FlagElement) {
		// width is an SVG attribute the flag typings do not declare
		return <FlagElement title={countryCode} className={className} {...{ width: 20 }} />;
	}
	console.error(`No flag for country ${countryCode} found!`);
	return null;
}

export { Flag };
