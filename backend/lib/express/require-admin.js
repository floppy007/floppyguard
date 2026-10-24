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
		} catch (err) {
			// 401s (invalid or revoked token) pass through so the client logs out
			// instead of seeing a misleading 403.
			next(
				err instanceof errs.UnauthorizedError || err instanceof errs.TokenRevokedError
					? err
					: new errs.PermissionError("Admin access required"),
			);
		}
	};
};
