import cn from "classnames";
import { Dark, Light, useTheme } from "src/hooks";
import styles from "./ThemeSwitcher.module.css";

interface Props {
	className?: string;
}
function ThemeSwitcher({ className }: Props) {
	const { theme, setTheme } = useTheme();
	const isDark = theme === Dark;

	return (
		<div className={cn(styles.toggle, className)}>
			<button
				type="button"
				className={cn(styles.opt, { [styles.optActive]: !isDark })}
				onClick={() => setTheme(Light)}
			>
				Light
			</button>
			<button
				type="button"
				className={cn(styles.opt, { [styles.optActive]: isDark })}
				onClick={() => setTheme(Dark)}
			>
				Dark
			</button>
		</div>
	);
}

export { ThemeSwitcher };
