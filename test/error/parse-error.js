var vows = require('vows');
var assert = require('assert');
var xmldom = require('xmldom');
var DOMParser = xmldom.DOMParser;
var DOMHandler = xmldom.__DOMHandler;
var ParseError = require('xmldom/sax').ParseError;
var getTestParser = require('../get-test-parser').getTestParser;

// ParseError is the error that is not caught by XMLReader (the SAX parser):
// an errorHandler (or DOMHandler) that throws it stops the parsing process.
// The default DOMHandler doesn't throw it, so the default DOMParser keeps reporting
// and parsing malformed input the way it did before (CVE-2021-21366).

/**
 * All methods implemented on the DOMHandler prototype.
 *
 * @type {string[]}
 */
var DOMHandlerMethods = Object.keys(DOMHandler.prototype).sort();

/**
 * XMLReader is currently not calling all methods "implemented" by DOMHandler (some are just empty),
 * If this changes the first test will fail.
 *
 * @type {string[]}
 */
var UNCALLED_METHODS = [
	'attributeDecl',
	'elementDecl',
	'endEntity',
	'externalEntityDecl',
	'getExternalSubset',
	'ignorableWhitespace',
	'internalEntityDecl',
	'notationDecl',
	'resolveEntity',
	'skippedEntity',
	'startEntity',
	'unparsedEntityDecl'
];

/**
 * Some of the methods DOMParser/XMLReader call during parsing are not guarded by try/catch,
 * hence an error happening in those will stop the parsing process.
 * There is a test to verify this error handling.
 * If it changes this list might need to be changed as well
 *
 * @type {string[]}
 */
var UNCAUGHT_METHODS = [
	'characters',
	'endDocument',
	'error',
	'setDocumentLocator',
	'startDocument'
];

/**
 * A subclass of DOMHandler that replaces all methods by stubs counting their calls.
 * As part of the constructor it can be told which method is supposed to throw an error
 * and which error constructor to use.
 */
function StubDOMHandler(throwingMethod, ErrorClass) {
	DOMHandler.call(this);
	var calls = this.calls = {};
	var self = this;
	DOMHandlerMethods.forEach(function (method) {
		calls[method] = 0;
		self[method] = function () {
			calls[method]++;
			if (method === throwingMethod) {
				throw new (ErrorClass || ParseError)('StubDOMHandler throwing in ' + throwingMethod);
			}
		};
	});
}
StubDOMHandler.prototype = new DOMHandler();

/**
 * This sample is triggering all method calls from XMLReader to DOMHandler at least once.
 * This is verified in a test.
 * The duplicate attribute is reported as error, the end tag that only matches when ignoring
 * the case is reported as fatalError and the comment at the end is not closed (error).
 */
var ALL_METHODS = '<?xml ?>\n' +
	'<!DOCTYPE name >\n' +
	'<![CDATA[ raw ]]>\n' +
	'<root xmlns="namespace">\n' +
	'  <!-- -->\n' +
	'  <element xmlns:x="http://test" x:a="" warning>\n' +
	'    character\n' +
	'  </element>\n' +
	'  <element duplicate="" duplicate="error"></element>\n' +
	'  <mismatch></MISMATCH></mismatch>\n' +
	'</root>\n' +
	'<!--\n';

function parseAllMethods(domBuilder) {
	return new DOMParser({domBuilder: domBuilder, locator: {}}).parseFromString(ALL_METHODS, 'text/xml');
}

var batch = {
	'should have name ParseError': function () {
		assert.equal(new ParseError('').name, 'ParseError');
	},
	'should be an instance of Error': function () {
		assert.ok(new ParseError('') instanceof Error);
	},
	'should be an instance of ParseError': function () {
		assert.ok(new ParseError('') instanceof ParseError);
	},
	'should store first argument as message': function () {
		assert.equal(new ParseError('FROM TEST').message, 'FROM TEST');
	},
	'should store second argument as locator': function () {
		var locator = {};
		assert.strictEqual(new ParseError('', locator).locator, locator);
	},
	'should have correct StackTrace': function () {
		var error = new ParseError('MESSAGE');
		var stack = error.stack && error.stack.split(/[\n\r]+/);
		assert.ok(stack && stack.length > 1, error.stack);
		assert.equal(stack[0], 'ParseError: MESSAGE');
		assert.ok(stack[1].indexOf(__filename) >= 0, stack[1]);
	},
	'Error should not be instanceof ParseError': function () {
		assert.ok(!(new Error() instanceof ParseError));
	},
	'the default DOMHandler does not throw for a not matching end tag (as before)': function () {
		['<a></b>', '<xml></XML></xml>'].forEach(function (source) {
			['text/xml', 'text/html'].forEach(function (mimeType) {
				var doc;
				assert.doesNotThrow(function () {
					doc = new DOMParser().parseFromString(source, mimeType);
				});
				assert.ok(doc && doc.documentElement, mimeType + ' ' + source + ': no document');
			});
		});
	},
	'the default DOMHandler reports a fatalError as error without throwing (as before)': function () {
		var domBuilder = new DOMHandler();
		var reported = [];
		domBuilder.error = function (msg) {
			reported.push(msg);
		};
		var doc = new DOMParser({domBuilder: domBuilder}).parseFromString('<xml><a/></XML><b/></xml>', 'text/xml');
		assert.equal(reported.length, 1, JSON.stringify(reported));
		assert.ok(/^element parse error: end tag name: XML is not match the current start tagName:xml/.test(reported[0]), reported[0]);
		assert.equal(doc.documentElement.tagName, 'xml');
	},
	'ParseError thrown in errorHandler.fatalError stops parsing': function () {
		var thrown;
		try {
			getTestParser({
				errorHandler: {
					fatalError: function (msg) {
						throw new ParseError(msg);
					}
				}
			}).parser.parseFromString('<xml></XML></xml>', 'text/xml');
		} catch (e) {
			thrown = e;
		}
		assert.ok(thrown instanceof ParseError, 'got: ' + thrown);
		assert.ok(/is not match the current start tagName/.test(thrown.message), thrown.message);
	},
	'should call "all possible" methods when using StubDOMHandler': function () {
		var domBuilder = new StubDOMHandler();

		parseAllMethods(domBuilder);

		var uncalled = DOMHandlerMethods.filter(function (method) {
			return domBuilder.calls[method] === 0;
		});
		assert.deepEqual(uncalled, UNCALLED_METHODS.slice().sort());
		['warning', 'error', 'fatalError'].forEach(function (level) {
			assert.ok(domBuilder.calls[level] > 0, level + ' was not called');
		});
	}
};

DOMHandlerMethods.filter(function (method) {
	return UNCALLED_METHODS.indexOf(method) < 0;
}).forEach(function (method) {
	batch['when DOMHandler.' + method + ' throws, should not catch ParseError'] = function () {
		var thrown;
		try {
			parseAllMethods(new StubDOMHandler(method, ParseError));
		} catch (e) {
			thrown = e;
		}
		assert.ok(thrown instanceof ParseError, 'got: ' + thrown);
		assert.equal(thrown.message, 'StubDOMHandler throwing in ' + method);
	};
	var isUncaughtMethod = UNCAUGHT_METHODS.indexOf(method) >= 0;
	batch['when DOMHandler.' + method + ' throws, ' + (isUncaughtMethod ? 'does not' : 'should') + ' catch other Error'] = function () {
		var domBuilder = new StubDOMHandler(method, Error);
		if (isUncaughtMethod) {
			assert.throws(function () {
				parseAllMethods(domBuilder);
			}, /StubDOMHandler throwing in /);
		} else {
			assert.doesNotThrow(function () {
				parseAllMethods(domBuilder);
			});
			assert.ok(domBuilder.calls.error > 0, 'error was not reported');
		}
	};
});

vows.describe('ParseError').addBatch(batch).run();
