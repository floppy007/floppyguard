import errs from "../error.js";

/**
 * Express middleware that ensures the authenticated user has the "admin" role.
 * Must be placed after jwtdecode() which populates res.locals.access.
 */
export default () => {
	return async (_, res, next) => {
		try {
			const access = res.locals.access;
			if (!access) {
				return next(new errs.AuthError("Authentication required"));
			}
			// Use the existing permission system — admin check via the
			// auditlog-list permission (requires admin role).
			await access.can("auditlog:list");
			next();
		} catch (_err) {
			next(new errs.PermissionError("Admin access required"));
		}
	};
};
