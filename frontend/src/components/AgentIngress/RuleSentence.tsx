import type { ReactNode } from "react";
import type { AgentIngressCatalog, AgentIngressRuleData } from "src/api/backend";
import { intl } from "src/locale/IntlProvider";
import { describeRule } from "./catalog";
import { ti } from "./utils";

/** At most this many targets inline, the rest as "+N more" with a tooltip. */
export const MAX_INLINE_TARGETS = 3;

interface Props {
	rule: Pick<AgentIngressRuleData, "sources" | "destinations" | "ports">;
	catalog?: AgentIngressCatalog | null;
	/** prefix the source ("Hinderlich Office may access …") — previews */
	withSource?: boolean;
	className?: string;
}

/** One rule as a sentence: "may access Ops-Server (10.3.10.25), Unraid – all ports". */
export function RuleSentence({ rule, catalog, withSource = false, className }: Props) {
	const d = describeRule(rule, catalog);
	const inline = d.targets.slice(0, MAX_INLINE_TARGETS);
	const more = d.targets.slice(MAX_INLINE_TARGETS);
	const targets: ReactNode[] = [];
	inline.forEach((t, i) => {
		if (i > 0) targets.push(", ");
		targets.push(<strong key={`t-${i}`}>{t}</strong>);
	});
	if (more.length) {
		targets.push(" ");
		targets.push(
			<span key="more" className="text-decoration-underline" title={more.join(", ")}>
				{ti("sentence.more", { count: more.length })}
				<span className="visually-hidden">: {more.join(", ")}</span>
			</span>,
		);
	}
	const body = d.anyTarget
		? intl.formatMessage({ id: "wireguard.agent.ingress.sentence.anything" }, { ports: d.portsText })
		: intl.formatMessage(
				{ id: "wireguard.agent.ingress.sentence.may-access" },
				{ targets: <span key="targets">{targets}</span>, ports: d.portsText },
			);
	return (
		<span className={className} data-testid="ingress-rule-sentence">
			{withSource && (
				<>
					<strong>{d.sourceLabel}</strong>{" "}
				</>
			)}
			{body}
		</span>
	);
}
