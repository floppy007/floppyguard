import styles from "./SiteContainer.module.css";

interface Props {
	children: React.ReactNode;
}
export function SiteContainer({ children }: Props) {
	return (
		<div className={styles.container}>
			<div className="container-xl py-3 min-w-0 platform-shell-accent">
				<div className="platform-shell-smoke" />
				<div className="platform-shell-body">
					{children}
				</div>
			</div>
		</div>
	);
}
