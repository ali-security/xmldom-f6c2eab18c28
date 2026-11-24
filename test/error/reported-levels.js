var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var ParseError = require('xmldom/sax').ParseError;
var getTestParser = require('../get-test-parser').getTestParser;
var REPORTED = require('./reported').REPORTED;

// Every sample in REPORTED is reported at its level, for text/xml and for text/html,
// and with the default errorHandler none of them stops the parser (as before CVE-2021-21366):
// only a ParseError thrown by a custom errorHandler does.

var MIME_TYPES = ['text/xml', 'text/html'];

function filterReported(reported, match) {
	return match ? (reported || []).filter(match) : reported;
}

function throwingHandler(thrown, ErrorClass) {
	return function (msg) {
		var toThrow = new ErrorClass(msg);
		thrown.push(toThrow);
		throw toThrow;
	};
}

var batch = {};

Object.keys(REPORTED).forEach(function (name) {
	var sample = REPORTED[name];
	var source = sample.source;
	var level = sample.level;
	var match = sample.match;
	MIME_TYPES.forEach(function (mimeType) {
		var prefix = name + ' with mimeType ' + mimeType + ' ';
		if (mimeType === 'text/html' && sample.skippedInHtml) {
			batch[prefix + 'should not be reported as ' + level] = function () {
				var p = getTestParser();

				p.parser.parseFromString(source, mimeType);

				// if no report was triggered, the key is not present on `errors`
				assert.strictEqual(p.errors[level], undefined, JSON.stringify(p.errors));
			};
			return;
		}
		batch[prefix + 'should be reported as ' + level] = function () {
			var p = getTestParser();

			p.parser.parseFromString(source, mimeType);

			var reported = filterReported(p.errors[level], match);
			assert.ok(reported, JSON.stringify(p.errors));
			assert.equal(reported.length, 1, JSON.stringify(p.errors));
		};
		batch[prefix + 'should not throw with the default errorHandler'] = function () {
			var doc;
			assert.doesNotThrow(function () {
				doc = new DOMParser().parseFromString(source, mimeType);
			});
			assert.ok(doc, 'no document returned');
		};
		if (level === 'fatalError') {
			batch[prefix + 'should not catch ParseError thrown in errorHandler.fatalError'] = function () {
				var thrown = [];
				var p = getTestParser({errorHandler: {fatalError: throwingHandler(thrown, ParseError)}});

				assert.throws(function () {
					p.parser.parseFromString(source, mimeType);
				}, ParseError);
				assert.equal(thrown.length, 1);
				assert.ok(match(thrown[0].message), thrown[0].message);
			};
			batch[prefix + 'should catch other Error thrown in errorHandler.fatalError and report it as error'] = function () {
				var errors = [];
				var p = getTestParser({
					errorHandler: {
						fatalError: throwingHandler([], Error),
						error: function (msg) {
							errors.push(msg);
						}
					}
				});

				p.parser.parseFromString(source, mimeType);

				assert.equal(errors.length, 1, JSON.stringify(errors));
				assert.ok(/element parse error: Error: /.test(errors[0]), errors[0]);
				assert.ok(match(errors[0]), errors[0]);
			};
		} else if (level === 'error') {
			batch[prefix + 'should not catch Error thrown in errorHandler.error'] = function () {
				var thrown = [];
				var p = getTestParser({errorHandler: {error: throwingHandler(thrown, Error)}});

				assert.throws(function () {
					p.parser.parseFromString(source, mimeType);
				}, Error);
				assert.ok(thrown.length > 0);
				assert.ok(match(thrown[0].toString()), thrown[0].toString());
			};
		} else if (level === 'warning') {
			batch[prefix + 'should escalate Error thrown in errorHandler.warning to errorHandler.error'] = function () {
				var thrown = [];
				var warnings = 0;
				var errors = 0;
				var warning = throwingHandler(thrown, Error);
				var p = getTestParser({
					errorHandler: {
						warning: function (msg) {
							warnings++;
							warning(msg);
						},
						error: function () {
							errors++;
						}
					}
				});

				p.parser.parseFromString(source, mimeType);

				assert.equal(warnings, 1);
				assert.equal(errors, 1);
				assert.ok(match(thrown[0].message), thrown[0].message);
			};
		}
	});
});

batch['custom errorHandler function with two args receives key and message'] = function () {
	var errors = {};
	var parser = new DOMParser({
		errorHandler: function (key, msg) {
			errors[key] = msg;
		}
	});

	parser.parseFromString(REPORTED.WF_AttributeMissingQuote.source, 'text/xml');
	assert.ok(errors.hasOwnProperty('warning'), JSON.stringify(errors));
	parser.parseFromString(REPORTED.SYNTAX_AttributeEqualMissingValue.source, 'text/xml');
	assert.ok(errors.hasOwnProperty('error'), JSON.stringify(errors));
	parser.parseFromString(REPORTED.WF_DuplicateAttribute.source, 'text/xml');
	assert.ok(REPORTED.WF_DuplicateAttribute.match(errors.error), JSON.stringify(errors));
	parser.parseFromString(REPORTED.WF_EndTagCaseMismatch.source, 'text/xml');
	assert.ok(errors.hasOwnProperty('fatalError'), JSON.stringify(errors));
};

batch['custom errorHandler function with one argument builds list'] = function () {
	var errors = [];
	var parser = new DOMParser({
		errorHandler: function (msg) {
			errors.push(msg);
		}
	});

	parser.parseFromString(REPORTED.WF_AttributeMissingQuote.source, 'text/xml');
	parser.parseFromString(REPORTED.SYNTAX_AttributeEqualMissingValue.source, 'text/xml');
	parser.parseFromString(REPORTED.WF_DuplicateAttribute.source, 'text/xml');
	parser.parseFromString(REPORTED.WF_EndTagCaseMismatch.source, 'text/xml');

	var expected = [
		/^\[xmldom warning\]/,
		/^\[xmldom error\]/,
		/^\[xmldom error\]\tAttribute a redefined/,
		/^\[xmldom fatalError\]/
	];
	assert.equal(errors.length, expected.length, JSON.stringify(errors));
	expected.forEach(function (pattern, i) {
		assert.ok(pattern.test(errors[i]), errors[i]);
	});
};

vows.describe('reported levels').addBatch(batch).run();
