import { IconKey, IconUserShield } from "@tabler/icons-react";
import { T } from "src/locale";

interface Props {
	sources?: string[];
}
export function AuthSourceFormatter({ sources }: Props) {
	const list = sources?.length ? sources : ["local"];
	return (
		<>
			{list.map((source) =>
				source === "sso" ? (
					<span key={source} className="badge bg-azure-lt me-1" title="OpenID Connect">
						<IconUserShield size={12} className="me-1" />
						<T id="user.source.sso" />
					</span>
				) : (
					<span key={source} className="badge bg-secondary-lt me-1">
						<IconKey size={12} className="me-1" />
						<T id="user.source.local" />
					</span>
				),
			)}
		</>
	);
}
