import Access from "../access.js";
import errs from "../error.js";

export default () => {
	return async (_, res, next) => {
		try {
			res.locals.access = null;
			const access = new Access(res.locals.token || null);
			await access.load();
			res.locals.access = access;
			next();
		} catch (err) {
			// Expired, malformed or foreign-key-signed token -> 401 so the SPA drops it (base.ts logoutOn401)
			next(new errs.UnauthorizedError(err instanceof errs.AuthError ? err.message : "Invalid token", err));
		}
	};
};
