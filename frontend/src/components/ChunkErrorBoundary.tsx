import { Component, type ErrorInfo, type ReactNode } from "react";
import { intl } from "src/locale/IntlProvider";
import { isChunkLoadError, reloadForNewBundle } from "src/modules/ChunkReload";

interface State {
	error: Error | null;
}

/**
 * Catches render errors of lazily loaded pages. Without it a failed chunk import
 * (stale tab after an app update) unmounts the whole app to a blank page.
 */
interface Props {
	children: ReactNode;
	/** Clears a shown error when it changes (e.g. the route path) */
	resetKey?: string;
}

export class ChunkErrorBoundary extends Component<Props, State> {
	state: State = { error: null };

	static getDerivedStateFromError(error: Error): State {
		return { error };
	}

	componentDidUpdate(prev: Props) {
		if (this.state.error && prev.resetKey !== this.props.resetKey) this.setState({ error: null });
	}

	componentDidCatch(error: Error, _info: ErrorInfo) {
		if (isChunkLoadError(error)) reloadForNewBundle();
	}

	render() {
		const { error } = this.state;
		if (!error) return this.props.children;
		return (
			<div className="container-tight py-4">
				<div className="alert alert-danger" role="alert">
					<div className="mb-2">
						{intl.formatMessage({ id: isChunkLoadError(error) ? "app.chunk-error" : "app.render-error" })}
					</div>
					<div className="small font-monospace text-secondary mb-2">{error.message}</div>
					<button type="button" className="btn btn-sm btn-primary" onClick={() => window.location.reload()}>
						{intl.formatMessage({ id: "app.reload" })}
					</button>
				</div>
			</div>
		);
	}
}
