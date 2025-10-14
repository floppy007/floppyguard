import cn from "classnames";
import { Dark, useTheme } from "src/hooks";

interface Props {
	alt: string;
	className?: string;
	variant?: "icon" | "wordmark";
}

const iconSrc = "/images/floppyguard-logo-sm.png";
const lightWordmarkSrc = "/images/floppyguard-logo-light.png";
const darkWordmarkSrc = "/images/floppyguard-logo-dark.png";

export function BrandLogo({ alt, className, variant = "wordmark" }: Props) {
	const { theme } = useTheme();

	if (variant === "icon") {
		return <img src={iconSrc} className={className} alt={alt} data-brand-logo="icon" />;
	}

	return (
		<img
			src={theme === Dark ? darkWordmarkSrc : lightWordmarkSrc}
			className={cn(className)}
			alt={alt}
			data-brand-logo="wordmark"
		/>
	);
}
