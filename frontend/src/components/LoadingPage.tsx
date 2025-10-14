import { Loading, Page } from "src/components";
import { useTheme } from "src/context";

interface Props {
	label?: string;
	noLogo?: boolean;
}
export function LoadingPage({ label, noLogo }: Props) {
	const { theme } = useTheme();

	return (
		<Page className="page-center">
			<div className={`container-tight py-4 ${theme === "dark" ? "loading-page-dark" : "loading-page-light"}`}>
				<Loading label={label} noLogo={noLogo} />
			</div>
		</Page>
	);
}
