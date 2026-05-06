import { IconBell, IconLock, IconLogout, IconShieldLock, IconUser } from "@tabler/icons-react";
import { BrandLogo, LocalePicker, NavLink, SiteMenu, ThemeSwitcher } from "src/components";
import { useAuthState } from "src/context";
import { useUser } from "src/hooks";
import { T } from "src/locale";
import { showChangePasswordModal, showTwoFactorModal, showUserModal } from "src/modals";
import styles from "./SiteHeader.module.css";

export function SiteHeader() {
	const { data: currentUser } = useUser("me");
	const isAdmin = currentUser?.roles.includes("admin");
	const { logout } = useAuthState();

	const initials = (currentUser?.nickname || "?")
		.split(/\s+/)
		.map((w) => w[0]?.toUpperCase())
		.slice(0, 2)
		.join("");

	return (
		<header className={`navbar navbar-expand-md d-print-none ${styles.header}`}>
			<div className={`container-xl ${styles.topRow}`}>
				<button
					className="navbar-toggler"
					type="button"
					data-bs-toggle="collapse"
					data-bs-target="#navbar-menu"
					aria-controls="navbar-menu"
					aria-expanded="false"
					aria-label="Toggle navigation"
				>
					<span className="navbar-toggler-icon" />
				</button>
				<div className={`navbar-brand navbar-brand-autodark pe-0 ${styles.brand}`}>
					<NavLink to="/">
						<div className={styles.logo}>
							<BrandLogo className={styles.logoImg} alt="FloppyGuard" />
						</div>
					</NavLink>
				</div>
				<SiteMenu className={styles.menuRow} />
				<div className={styles.tools}>
					<div className={styles.toolsRail}>
						<div className="nav-item d-none d-md-block">
							<ThemeSwitcher />
						</div>
						<div className="nav-item d-none d-md-block">
							<LocalePicker />
						</div>
						<button type="button" className={styles.btnIcon} title="Notifications">
							<IconBell size={15} />
						</button>
					</div>
					<div className="nav-item d-md-flex">
						<div className="nav-item dropdown">
							<a
								href="/"
								className={styles.profileLink}
								data-bs-toggle="dropdown"
								aria-label="Open user menu"
							>
								{currentUser?.avatar ? (
									<span
										className={styles.profileAvatar}
										style={{
											backgroundImage: `url(${currentUser.avatar})`,
											backgroundSize: "cover",
										}}
									/>
								) : (
									<span className={styles.profileAvatar}>{initials}</span>
								)}
							</a>
							<div className="dropdown-menu dropdown-menu-end dropdown-menu-arrow">
								<div className="d-md-none">
									{/* biome-ignore lint/a11y/noStaticElementInteractions lint/a11y/useKeyWithClickEvents: wrapper */}
									<div
										className="p-2 pb-1 pe-1 d-flex align-items-center"
										onClick={(e) => e.stopPropagation()}
									>
										<div className="ps-2 pe-1 me-auto">
											<div>{currentUser?.nickname}</div>
											<div className="mt-1 small text-secondary text-nowrap">
												<T id={isAdmin ? "role.admin" : "role.standard-user"} />
											</div>
										</div>
										<div className="d-flex align-items-center">
											<ThemeSwitcher className="me-n2" />
											<LocalePicker menuAlign="end" />
										</div>
									</div>
									<div className="dropdown-divider" />
								</div>
								<a
									href="?"
									className="dropdown-item"
									onClick={(e) => {
										e.preventDefault();
										showUserModal("me");
									}}
								>
									<IconUser width={18} />
									<T id="user.edit-profile" />
								</a>
								<a
									href="?"
									className="dropdown-item"
									onClick={(e) => {
										e.preventDefault();
										showChangePasswordModal("me");
									}}
								>
									<IconLock width={18} />
									<T id="user.change-password" />
								</a>
								<a
									href="?"
									className="dropdown-item"
									onClick={(e) => {
										e.preventDefault();
										showTwoFactorModal("me");
									}}
								>
									<IconShieldLock width={18} />
									<T id="user.two-factor" />
								</a>
								<div className="dropdown-divider" />
								<a
									href="?"
									className="dropdown-item"
									onClick={(e) => {
										e.preventDefault();
										logout();
									}}
								>
									<IconLogout width={18} />
									<T id="user.logout" />
								</a>
							</div>
						</div>
					</div>
				</div>
			</div>
		</header>
	);
}
