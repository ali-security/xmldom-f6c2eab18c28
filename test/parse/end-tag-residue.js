var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;

// CVE-2026-83611: the XML `ETag` production is `'</' Name S? '>'`: only optional whitespace may
// follow the `Name`. A valid `Name` followed by whitespace and non-whitespace residue (e.g.
// `</a\njunk>` or `</a junk>`) is not well-formed, but it was silently accepted (the malformed end
// tag ignored, the residue dropped), so a parse-before-trust well-formedness gate built on the
// errorHandler could be bypassed. It is now reported as a recoverable `error` (in both XML and
// HTML) while parsing recovers to the same DOM as before.
// https://www.w3.org/TR/2008/REC-xml-20081126/#NT-ETag

var TRAILING_CONTENT = /followed by whitespace and trailing content/;

function getTestParser() {
	var errors = {};
	function collect(level) {
		return function (msg) {
			(errors[level] = errors[level] || []).push(msg);
		};
	}
	var parser = new DOMParser({
		locator: {},
		errorHandler: {
			warning: collect('warning'),
			error: collect('error'),
			fatalError: collect('fatalError')
		}
	});
	return {errors: errors, parser: parser};
}

function someMatch(messages, pattern) {
	if (!messages) {
		return false;
	}
	for (var i = 0; i < messages.length; i++) {
		if (pattern.test(messages[i])) {
			return true;
		}
	}
	return false;
}

function assertReported(source, mimeType) {
	var clean = new DOMParser({errorHandler: function () {}})
		.parseFromString('<a></a>', mimeType).toString();
	var p = getTestParser();
	var doc = p.parser.parseFromString(source, mimeType);
	assert.ok(someMatch(p.errors.error, TRAILING_CONTENT),
		'expected an error for ' + JSON.stringify(source) + ' (' + mimeType + '), got: ' +
		JSON.stringify(p.errors));
	assert.strictEqual(p.errors.fatalError, undefined);
	assert.equal(doc.toString(), clean);
}

function assertNotReported(source, mimeType, expected) {
	var p = getTestParser();
	var doc = p.parser.parseFromString(source, mimeType);
	assert.strictEqual(p.errors.error, undefined, 'unexpected error: ' + JSON.stringify(p.errors.error));
	assert.strictEqual(p.errors.fatalError, undefined);
	assert.equal(doc.toString(), expected);
}

var WHITESPACE = [
	['a space', ' '],
	['a tab', '\t'],
	['a line feed', '\n'],
	['a carriage return', '\r']
];

var residue = {};
WHITESPACE.forEach(function (entry) {
	var label = entry[0];
	var source = '<a></a' + entry[1] + 'junk>';
	residue['reports a recoverable error for ' + label + ' residue (text/xml) and recovers to the same DOM'] = function () {
		assertReported(source, 'text/xml');
	};
	residue['reports a recoverable error for ' + label + ' residue (text/html) and recovers to the same DOM'] = function () {
		assertReported(source, 'text/html');
	};
});

vows.describe('end tag with trailing residue after the name').addBatch(residue).addBatch({
	'reports the whole end tag content in the error message': function () {
		var p = getTestParser();
		p.parser.parseFromString('<a></a\nbogus>', 'text/xml');
		assert.equal(p.errors.error.length, 1, JSON.stringify(p.errors.error));
		assert.ok(p.errors.error[0].indexOf('[xmldom error]\tend tag name is followed by whitespace ' +
			'and trailing content: "a\nbogus"') === 0, p.errors.error[0]);
	},
	'reports residue after multiple whitespace characters and nested end tags': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString('<root><a></a \r\n\tjunk="x"></root>', 'text/xml');
		assert.ok(someMatch(p.errors.error, TRAILING_CONTENT), JSON.stringify(p.errors));
		assert.strictEqual(doc.getElementsByTagName('a').length, 1);
	},
	'an errorHandler that throws on error rejects the document (parse-before-trust gate)': function () {
		var parser = new DOMParser({
			errorHandler: {
				warning: function () {},
				error: function (msg) {
					throw new Error(msg);
				},
				fatalError: function (msg) {
					throw new Error(msg);
				}
			}
		});
		assert['throws'](function () {
			parser.parseFromString('<a></a\njunk>', 'text/xml');
		}, TRAILING_CONTENT);
	}
}).addBatch({
	'does not report a clean end tag': function () {
		assertNotReported('<a></a>', 'text/xml', '<a/>');
	},
	'does not report a clean end tag of a nested element': function () {
		assertNotReported('<a><b/></a>', 'text/xml', '<a><b/></a>');
	},
	'does not report an end tag with only trailing whitespace': function () {
		assertNotReported('<a></a\r\n>', 'text/xml', '<a/>');
		assertNotReported('<a></a \t>', 'text/xml', '<a/>');
	}
}).addBatch({
	// The guard runs on the untrimmed end tag content (everything up to `>`), so it must stay
	// linear on a long whitespace run; a backtracking `[ \t\n\r]+[^ \t\n\r]` took seconds here.
	'checks an end tag with a long whitespace run in linear time': function () {
		var spaces = new Array(80001).join(' ');
		var start = Date.now();
		assertNotReported('<a></a' + spaces + '>', 'text/xml', '<a/>');
		var p = getTestParser();
		p.parser.parseFromString('<a></a' + spaces + 'junk>', 'text/xml');
		var elapsed = Date.now() - start;
		assert.ok(someMatch(p.errors.error, TRAILING_CONTENT), JSON.stringify(p.errors));
		assert.ok(elapsed < 1000, 'parsing took ' + elapsed + 'ms');
	}
}).run();
