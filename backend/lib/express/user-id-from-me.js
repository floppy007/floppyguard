import errs from "../error.js";

export default (req, res, next) => {
	if (req.params.user_id === "me") {
		const userId = res.locals.access?.token?.getUserId(0) || 0;
		if (!userId) {
			// No/empty token: deny here instead of letting `null.id` throw a 500
			return next(new errs.PermissionError("Permission Denied"));
		}
		req.params.user_id = userId;
	} else {
		const id = Number.parseInt(req.params.user_id, 10);
		if (!Number.isInteger(id) || id < 1) {
			// NaN/0 would make internalUser.get() fall back to the token user
			return next(new errs.ValidationError("Invalid user id"));
		}
		req.params.user_id = id;
	}
	next();
};
