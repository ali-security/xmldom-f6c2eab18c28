var DOMParser = require('xmldom').DOMParser;

/**
 * Creates a DOMParser with a locator and an errorHandler for tests.
 *
 * Without an errorHandler in `options`, every reported message is collected in `errors`,
 * grouped by the name of the errorHandler method that was called:
 * if nothing was reported at a level, `errors` has no key for that level.
 *
 * @param {Object} [options]
 * @param {Object} [options.errorHandler] used instead of the one collecting into `errors`
 * @param {Object} [options.locator] defaults to `{}`
 * @returns {{errors: Object, parser: DOMParser}}
 */
function getTestParser(options) {
	options = options || {};
	var errors = {};
	var errorHandler = options.errorHandler;
	if (!errorHandler) {
		errorHandler = {};
		['warning', 'error', 'fatalError'].forEach(function (level) {
			errorHandler[level] = function (msg) {
				(errors[level] = errors[level] || []).push(msg);
			};
		});
	}
	return {
		errors: errors,
		parser: new DOMParser({errorHandler: errorHandler, locator: options.locator || {}})
	};
}

module.exports = {
	getTestParser: getTestParser
};
