// Serializes check-then-insert/patch on user.email. The user table has no unique
// index on email and the backend is one node process, so a module mutex closes
// the race between isEmailAvailable()/SELECT and the following INSERT/PATCH.
let _lock = Promise.resolve();
export const withUserEmailLock = (fn) => {
	const next = _lock.then(fn, fn);
	_lock = next.catch(() => {});
	return next;
};
