import fileUpload from "express-fileupload";

/**
 * Datei-Uploads nur dort annehmen, wo sie gebraucht werden, und erst nach der
 * Berechtigungsprüfung der Route. Ohne Grenzen hält express-fileupload den
 * gesamten Body im Speicher.
 *
 * @param {{fileSize: number, files: number}} limits
 */
const limitedFileUpload = ({ fileSize, files }) =>
	fileUpload({
		limits: { fileSize, files, fields: 20, parts: files + 20 },
		abortOnLimit: true,
		responseOnLimit: "File too large",
	});

export default limitedFileUpload;
