import {
	IconArrowsRight,
	IconChartBar,
	IconChevronRight,
	IconDeviceDesktop,
	IconHome,
	IconLayoutGrid,
	IconLock,
	IconSettings,
	IconShield,
	IconUser,
	IconVectorBezier2,
} from "@tabler/icons-react";
import cn from "classnames";
import React, { useEffect, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { HasPermission, NavLink } from "src/components";
import { T } from "src/locale";
import {
	ACCESS_LISTS,
	ADMIN,
	CERTIFICATES,
	DEAD_HOSTS,
	type MANAGE,
	PROXY_HOSTS,
	REDIRECTION_HOSTS,
	type Section,
	STREAMS,
	VIEW,
} from "src/modules/Permissions";
import styles from "./SiteMenu.module.css";

interface MenuItem {
	label: string;
	icon?: React.ElementType;
	/** Render a custom icon element instead of an icon component */
	iconElement?: React.ReactNode;
	to?: string;
	items?: MenuItem[];
	permissionSection?: Section | typeof ADMIN;
	permission?: typeof VIEW | typeof MANAGE;
	/** Show only the icon, hide the label text */
	iconOnly?: boolean;
}

const NpmLogoIcon = () => (
	<img src="/images/logo-no-text.svg" width={16} height={16} alt="NPM" style={{ display: "block" }} />
);

const WireGuardIcon = () => (
	<img src="/images/wireguard-icon.svg" width={16} height={16} alt="WG" style={{ display: "block" }} />
);

const getSubitemIcon = (label: string) => {
	switch (label) {
		case "proxy-hosts":
			return IconDeviceDesktop;
		case "redirection-hosts":
			return IconArrowsRight;
		case "streams":
			return IconVectorBezier2;
		case "dead-hosts":
			return IconHome;
		case "access-lists":
			return IconShield;
		case "certificates":
			return IconLock;
		case "users":
			return IconUser;
		case "auditlogs":
			return IconChartBar;
		case "settings":
			return IconSettings;
		case "wireguard":
			return IconShield;
		default:
			return IconChevronRight;
	}
};

const menuItems: MenuItem[] = [
	{
		to: "/",
		icon: IconLayoutGrid,
		label: "dashboard",
	},
	{
		to: "/traffic",
		icon: IconChartBar,
		label: "traffic",
	},
	{
		iconElement: <NpmLogoIcon />,
		label: "hosts",
		items: [
			{
				to: "/nginx/proxy",
				label: "proxy-hosts",
				permissionSection: PROXY_HOSTS,
				permission: VIEW,
			},
			{
				to: "/nginx/redirection",
				label: "redirection-hosts",
				permissionSection: REDIRECTION_HOSTS,
				permission: VIEW,
			},
			{
				to: "/nginx/stream",
				label: "streams",
				permissionSection: STREAMS,
				permission: VIEW,
			},
			{
				to: "/nginx/404",
				label: "dead-hosts",
				permissionSection: DEAD_HOSTS,
				permission: VIEW,
			},
		],
	},
	{
		to: "/wireguard",
		iconElement: <WireGuardIcon />,
		label: "wireguard",
	},
	{
		icon: IconSettings,
		label: "settings",
		permissionSection: ADMIN,
		items: [
			{
				to: "/access",
				label: "access-lists",
				permissionSection: ACCESS_LISTS,
				permission: VIEW,
			},
			{
				to: "/certificates",
				label: "certificates",
				permissionSection: CERTIFICATES,
				permission: VIEW,
			},
			{
				to: "/users",
				label: "users",
				permissionSection: ADMIN,
			},
			{
				to: "/audit-log",
				label: "auditlogs",
				permissionSection: ADMIN,
			},
			{
				to: "/settings",
				label: "settings",
				permissionSection: ADMIN,
			},
		],
	},
];

const renderIcon = (item: MenuItem, size = 16) => {
	if (item.iconElement) return item.iconElement;
	if (item.icon) return React.createElement(item.icon, { size });
	return null;
};

const pathMatches = (currentPath: string, targetPath?: string) => {
	if (!targetPath) {
		return false;
	}
	if (targetPath === "/") {
		return currentPath === "/";
	}
	return currentPath === targetPath || currentPath.startsWith(`${targetPath}/`);
};

const hasActiveChild = (currentPath: string, item: MenuItem) =>
	Boolean(item.items?.some((subitem) => pathMatches(currentPath, subitem.to)));

const getMenuItem = (
	item: MenuItem,
	currentPath: string,
	onClick?: () => void,
	openDropdownLabel?: string | null,
	onToggleDropdown?: (label: string) => void,
	onCloseDropdown?: () => void,
) => {
	if (item.items && item.items.length > 0) {
		return getMenuDropown(item, currentPath, onClick, openDropdownLabel, onToggleDropdown, onCloseDropdown);
	}

	const isActive = pathMatches(currentPath, item.to);

	return (
		<HasPermission
			key={`item-${item.label}`}
			section={item.permissionSection}
			permission={item.permission || VIEW}
			hideError
		>
			<li className={cn("nav-item", styles.item)}>
				<NavLink
					to={item.to}
					onClick={onClick}
					className={cn("nav-link", styles.itemLink, {
						[styles.itemActive]: isActive,
					})}
				>
					<span className={styles.icon}>{renderIcon(item)}</span>
					{!item.iconOnly && (
						<span className="nav-link-title">
							<T id={item.label} />
						</span>
					)}
				</NavLink>
			</li>
		</HasPermission>
	);
};

const getMenuDropown = (
	item: MenuItem,
	currentPath: string,
	onClick?: () => void,
	openDropdownLabel?: string | null,
	onToggleDropdown?: (label: string) => void,
	onCloseDropdown?: () => void,
) => {
	const cns = cn("nav-item", "dropdown");
	const isActive = hasActiveChild(currentPath, item);
	const isOpen = openDropdownLabel === item.label;
	return (
		<HasPermission
			key={`item-${item.label}`}
			section={item.permissionSection}
			permission={item.permission || VIEW}
			hideError
		>
			<li className={cn(cns, styles.item)}>
				<button
					type="button"
					className={cn("nav-link", styles.dropdownToggle, styles.itemLink, {
						[styles.itemActive]: isActive,
						[styles.itemOpen]: isOpen,
					})}
					aria-expanded={isOpen ? "true" : "false"}
					onClick={() => {
						if (onToggleDropdown) {
							onToggleDropdown(item.label);
						}
					}}
				>
					<span className={styles.icon}>{renderIcon(item)}</span>
					<span className="nav-link-title">
						<T id={item.label} />
					</span>
				</button>
				<div
					className={cn(styles.dropdownPanel, {
						[styles.dropdownPanelOpen]: isOpen,
					})}
				>
					<div className={styles.dropdownList}>
						{item.items?.map((subitem, idx) => {
							const subitemActive = pathMatches(currentPath, subitem.to);
							const SubitemIcon = getSubitemIcon(subitem.label);
							return (
								<HasPermission
									key={`${idx}-${subitem.to}`}
									section={subitem.permissionSection}
									permission={subitem.permission || VIEW}
									hideError
								>
									<NavLink
										to={subitem.to}
										isDropdownItem
										onClick={() => {
											if (onCloseDropdown) {
												onCloseDropdown();
											}
											if (onClick) {
												onClick();
											}
										}}
										className={cn("dropdown-item", styles.dropdownItem, {
											active: subitemActive,
										})}
									>
										<span className={styles.dropdownItemIcon}>
											<SubitemIcon size={16} />
										</span>
										<span className={styles.dropdownItemLabel}>
											<T id={subitem.label} />
										</span>
										<span className={styles.dropdownItemArrow}>
											<IconChevronRight size={15} />
										</span>
									</NavLink>
								</HasPermission>
							);
						})}
					</div>
				</div>
			</li>
		</HasPermission>
	);
};

interface SiteMenuProps {
	className?: string;
}

export function SiteMenu({ className }: SiteMenuProps) {
	const location = useLocation();
	const [openDropdownLabel, setOpenDropdownLabel] = useState<string | null>(null);
	const menuRef = useRef<HTMLDivElement | null>(null);

	useEffect(() => {
		setOpenDropdownLabel(null);
	}, []);

	useEffect(() => {
		const handlePointerDown = (event: MouseEvent) => {
			if (!menuRef.current?.contains(event.target as Node)) {
				setOpenDropdownLabel(null);
			}
		};

		document.addEventListener("mousedown", handlePointerDown);
		return () => {
			document.removeEventListener("mousedown", handlePointerDown);
		};
	}, []);

	const closeMenu = () =>
		setTimeout(() => {
			const navbarToggler = document.querySelector<HTMLElement>(".navbar-toggler");
			const navbarMenu = document.querySelector("#navbar-menu");
			if (navbarToggler && navbarMenu?.classList.contains("show")) {
				navbarToggler.click();
			}
		}, 300);

	return (
		<div ref={menuRef} className={cn("collapse", "navbar-collapse", styles.menu, className)} id="navbar-menu">
			<div className={styles.menuInner}>
				<ul className={cn("navbar-nav", styles.nav)}>
					{menuItems.length > 0 &&
						menuItems.map((item) => {
							return getMenuItem(
								item,
								location.pathname,
								closeMenu,
								openDropdownLabel,
								(label) => setOpenDropdownLabel((current) => (current === label ? null : label)),
								() => setOpenDropdownLabel(null),
							);
						})}
				</ul>
			</div>
		</div>
	);
}
