var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
var ParseError = require('xmldom/sax').ParseError;
var getTestParser = require('../get-test-parser').getTestParser;

// CVE-2021-21366: an attribute name must not appear more than once in the same
// start-tag. xmldom used the first declaration of a namespace but the last value of
// the attribute, so a document with duplicates did not keep its namespaces when it
// was parsed and serialized again.
// A redefined attribute is reported as error (the parser does not stop, as before),
// and its last value is used for the namespace as well as in the DOM.

var MIME_TYPES = ['text/xml', 'text/html'];

function redefined(messages, qName) {
	return (messages || []).filter(function (msg) {
		return msg.indexOf('Attribute ' + qName + ' redefined') >= 0;
	});
}

function assertReportedAsError(source, mimeType, qName) {
	var p = getTestParser();
	var doc = p.parser.parseFromString(source, mimeType);
	assert.ok(doc && doc.documentElement, mimeType + ' ' + source + ': no document');
	assert.equal(redefined(p.errors.error, qName).length, 1, mimeType + ' ' + source + ': ' + JSON.stringify(p.errors));
	assert.strictEqual(p.errors.fatalError, undefined, mimeType + ' ' + source + ': ' + JSON.stringify(p.errors));
	return doc;
}

function serialize(doc) {
	return new XMLSerializer().serializeToString(doc);
}

vows.describe('duplicate attribute').addBatch({
	'duplicate attribute does not throw with the default errorHandler': function () {
		[
			['<xml a="1" a="2"></xml>', 'text/xml'],
			['<xml a="1" a="2"></xml>', 'text/html'],
			['<div class="1" class="2"></div>', 'text/html'],
			['<xml xmlns="http://a" xmlns="http://b"><child/></xml>', 'text/xml']
		].forEach(function (sample) {
			var doc;
			assert.doesNotThrow(function () {
				doc = new DOMParser().parseFromString(sample[0], sample[1]);
			});
			assert.ok(doc && doc.documentElement, sample[1] + ' ' + sample[0] + ': no document');
		});
	},
	'the last value of a duplicate attribute wins in the DOM': function () {
		MIME_TYPES.forEach(function (mimeType) {
			var el = assertReportedAsError('<xml a="1" b="b" a="2"></xml>', mimeType, 'a').documentElement;
			assert.equal(el.getAttribute('a'), '2', mimeType);
			assert.equal(el.getAttribute('b'), 'b', mimeType);
			assert.equal(el.attributes.length, 2, mimeType);
		});
		var div = assertReportedAsError('<div class="1" class="2"></div>', 'text/html', 'class').documentElement;
		assert.equal(div.getAttribute('class'), '2');
		assert.equal(div.attributes.length, 1);
	},
	'duplicate attribute is reported as error for every way of writing an attribute': function () {
		MIME_TYPES.forEach(function (mimeType) {
			// quoted values
			assertReportedAsError('<xml a="1" a=\'2\'></xml>', mimeType, 'a');
			// values missing the start quote
			assertReportedAsError('<xml a=1" a=2"></xml>', mimeType, 'a');
			// unquoted values, followed by space and by the end of the tag
			assertReportedAsError('<xml a=1 a=2></xml>', mimeType, 'a');
			// unquoted values, followed by space and by a self closing tag
			assertReportedAsError('<xml a=1 a=2 />', mimeType, 'a');
			// attributes without value
			assertReportedAsError('<xml a a></xml>', mimeType, 'a');
			assertReportedAsError('<xml a a />', mimeType, 'a');
			// attribute without value and with value
			assertReportedAsError('<xml a a="1"></xml>', mimeType, 'a');
			// prefixed attribute
			assertReportedAsError('<xml xmlns:p="http://p" p:a="1" p:a="2"/>', mimeType, 'p:a');
		});
	},
	'duplicate default namespace declaration: the last one is used and kept by serializing': function () {
		var source = '<xml xmlns="http://a" xmlns="http://b"><child/></xml>';
		var doc = assertReportedAsError(source, 'text/xml', 'xmlns');
		var root = doc.documentElement;
		assert.equal(root.namespaceURI, 'http://b');
		assert.equal(root.getAttribute('xmlns'), 'http://b');
		assert.equal(root.firstChild.namespaceURI, 'http://b');
		var serialized = serialize(doc);
		assert.equal(serialized, '<xml xmlns="http://b"><child/></xml>');
		var again = new DOMParser().parseFromString(serialized, 'text/xml');
		assert.equal(again.documentElement.namespaceURI, 'http://b');
		assert.equal(again.documentElement.firstChild.namespaceURI, 'http://b');
		assert.equal(serialize(again), serialized);
	},
	'duplicate prefixed namespace declaration: the last one is used and kept by serializing': function () {
		var source = '<p:xml xmlns:p="http://a" xmlns:p="http://b" p:a="1"><p:child/></p:xml>';
		var doc = assertReportedAsError(source, 'text/xml', 'xmlns:p');
		var root = doc.documentElement;
		assert.equal(root.namespaceURI, 'http://b');
		assert.equal(root.getAttribute('xmlns:p'), 'http://b');
		assert.equal(root.getAttributeNode('p:a').namespaceURI, 'http://b');
		assert.equal(root.firstChild.namespaceURI, 'http://b');
		var serialized = serialize(doc);
		assert.equal(serialized, '<p:xml xmlns:p="http://b" p:a="1"><p:child/></p:xml>');
		var again = new DOMParser().parseFromString(serialized, 'text/xml');
		assert.equal(again.documentElement.namespaceURI, 'http://b');
		assert.equal(again.documentElement.firstChild.namespaceURI, 'http://b');
		assert.equal(serialize(again), serialized);
	},
	'two arguments function errorHandler receives error': function () {
		var errors = {};
		new DOMParser({
			errorHandler: function (key, msg) {
				errors[key] = msg;
			}
		}).parseFromString('<xml a="1" a="2"></xml>', 'text/xml');
		assert.ok(/Attribute a redefined/.test(errors.error), JSON.stringify(errors));
		assert.ok(!errors.hasOwnProperty('fatalError'), JSON.stringify(errors));
	},
	'one argument function errorHandler receives error': function () {
		var errors = [];
		new DOMParser({
			errorHandler: function (msg) {
				errors.push(msg);
			}
		}).parseFromString('<xml a="1" a="2"></xml>', 'text/xml');
		assert.equal(errors.length, 1, JSON.stringify(errors));
		assert.ok(/^\[xmldom error\]\tAttribute a redefined/.test(errors[0]), errors[0]);
	},
	'errorHandler.error can stop parsing by throwing ParseError': function () {
		var thrown;
		try {
			new DOMParser({
				locator: {},
				errorHandler: {
					error: function (msg) {
						throw new ParseError(msg);
					}
				}
			}).parseFromString('<xml>\n<child a="1" a="2"/></xml>', 'text/xml');
		} catch (e) {
			thrown = e;
		}
		assert.ok(thrown instanceof ParseError, 'got: ' + thrown);
		assert.ok(/Attribute a redefined/.test(thrown.message), thrown.message);
		assert.ok(/line:2/.test(thrown.message), thrown.message);
	},
	'distinct attributes are not reported': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString(
			'<xml xmlns="http://a" xmlns:p="http://p" xmlns:q="http://q" a="1" p:a="2" q:a="3"' +
			' constructor="c" toString="t" valueOf="v" hasOwnProperty="h"/>', 'text/xml');
		assert.deepEqual(p.errors, {}, JSON.stringify(p.errors));
		var el = doc.documentElement;
		assert.equal(el.namespaceURI, 'http://a');
		assert.equal(el.getAttribute('a'), '1');
		assert.equal(el.getAttributeNS('http://p', 'a'), '2');
		assert.equal(el.getAttributeNS('http://q', 'a'), '3');
		assert.equal(el.getAttribute('constructor'), 'c');
		assert.equal(el.getAttribute('toString'), 't');
		assert.equal(el.getAttribute('valueOf'), 'v');
		assert.equal(el.getAttribute('hasOwnProperty'), 'h');
	},
	'namespace prefixes named like Object.prototype members are not mixed up': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString(
			'<xml xmlns:constructor="http://c" xmlns:toString="http://t" constructor:a="1" toString:a="2"/>', 'text/xml');
		assert.deepEqual(p.errors, {}, JSON.stringify(p.errors));
		var el = doc.documentElement;
		assert.equal(el.getAttributeNS('http://c', 'a'), '1');
		assert.equal(el.getAttributeNS('http://t', 'a'), '2');
	},
	'same attribute on different elements is not reported': function () {
		var p = getTestParser();
		p.parser.parseFromString('<xml a="1" xmlns="http://a"><child a="2" xmlns="http://b"/></xml>', 'text/xml');
		assert.deepEqual(p.errors, {}, JSON.stringify(p.errors));
	}
}).run();
