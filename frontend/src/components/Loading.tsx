import type { ReactNode } from "react";
import { BrandLogo } from "src/components/BrandLogo";
import { T } from "src/locale";
import styles from "./Loading.module.css";

interface Props {
	label?: string | ReactNode;
	noLogo?: boolean;
}
export function Loading({ label, noLogo }: Props) {
	return (
		<div className="empty text-center">
			{noLogo ? null : (
				<div className="mb-3">
					<BrandLogo className={styles.logo} alt="FloppyGuard Platform" />
				</div>
			)}
			<div className="text-secondary mb-3">{label || <T id="loading" />}</div>
			<div className="progress progress-sm">
				<div className="progress-bar progress-bar-indeterminate" />
			</div>
		</div>
	);
}
