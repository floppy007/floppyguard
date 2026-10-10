import React from "react";
import { createRoot } from "react-dom/client";
import App from "src/App.tsx";
import { reloadForNewBundle } from "src/modules/ChunkReload";

import "@tabler/core/dist/css/tabler.min.css";
import "@tabler/core/dist/js/tabler.min.js";
import "./App.css";

// A stale tab after an app update requests chunks that no longer exist
window.addEventListener("vite:preloadError", (event) => {
	if (reloadForNewBundle()) event.preventDefault();
});

createRoot(document.getElementById("root") as HTMLElement).render(
	<React.StrictMode>
		<App />
	</React.StrictMode>,
);
