import cn from "classnames";
import { Dark, Light, useTheme } from "src/hooks";
import { T } from "src/locale";
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
				<T id="theme.light" />
			</button>
			<button
				type="button"
				className={cn(styles.opt, { [styles.optActive]: isDark })}
				onClick={() => setTheme(Dark)}
			>
				<T id="theme.dark" />
			</button>
		</div>
	);
}

export { ThemeSwitcher };
