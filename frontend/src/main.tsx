import React from "react";
import { createRoot } from "react-dom/client";
import App from "src/App.tsx";

import "@tabler/core/dist/css/tabler.min.css";
import "@tabler/core/dist/js/tabler.min.js";
import "./App.css";

createRoot(document.getElementById("root") as HTMLElement).render(
	<React.StrictMode>
		<App />
	</React.StrictMode>,
);
