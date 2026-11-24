var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
var dom = require('xmldom/dom');
var DOMImplementation = dom.DOMImplementation;
var DOMException = dom.DOMException;

// CVE-2026-34601: Document.createCDATASection accepted data containing "]]>",
// which terminates the CDATA section when serialized, so attacker controlled
// data could inject arbitrary markup (elements, attributes, ...) into the
// serialized XML.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-wh4c-j3r5-mjhp

// the code is a literal so the vows report the missing check (and not a
// TypeError) when DOMException is not exported
var INVALID_CHARACTER_ERR = 5;

function assertThrowsDOMException(code, fn) {
	var thrown = null;
	try {
		fn();
	} catch (e) {
		thrown = e;
	}
	assert.ok(thrown, 'expected a DOMException with code ' + code + ' to be thrown');
	assert.strictEqual(thrown.code, code, 'unexpected exception: ' + thrown);
	return thrown;
}

function createDocument() {
	return new DOMImplementation().createDocument(null, 'xml');
}

vows.describe('Document.prototype.createCDATASection').addBatch({
	'throws InvalidCharacterError': {
		'when data is exactly "]]>"': function () {
			var doc = createDocument();
			assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
				doc.createCDATASection(']]>');
			});
		},
		'when data starts with safe content then contains "]]>"': function () {
			var doc = createDocument();
			assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
				doc.createCDATASection('safe]]>data');
			});
		},
		'when data contains multiple "]]>" occurrences': function () {
			var doc = createDocument();
			assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
				doc.createCDATASection('before]]>after]]>after');
			});
		},
		'with the DOMException code INVALID_CHARACTER_ERR': function () {
			var doc = createDocument();
			assert.strictEqual(DOMException.INVALID_CHARACTER_ERR, INVALID_CHARACTER_ERR);
			var thrown = assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
				doc.createCDATASection(']]>');
			});
			assert.ok(thrown instanceof DOMException, 'got: ' + thrown);
		}
	},
	'does not throw': {
		'when data is safe': function () {
			var doc = createDocument();
			var cdata = doc.createCDATASection('safe');
			assert.strictEqual(cdata.nodeType, 4);
			assert.strictEqual(cdata.data, 'safe');
		},
		'when data is empty string': function () {
			var doc = createDocument();
			var cdata = doc.createCDATASection('');
			assert.strictEqual(cdata.data, '');
		},
		'when data contains "]]" or "]>" without "]]>"': function () {
			var doc = createDocument();
			assert.strictEqual(doc.createCDATASection(']] ]>').data, ']] ]>');
		}
	},
	'injection through the created section': {
		'is prevented, no element is injected into the serialized XML': function () {
			var doc = new DOMImplementation().createDocument(null, 'root', null);
			var payload = ']]><injected/><![CDATA[';
			assertThrowsDOMException(INVALID_CHARACTER_ERR, function () {
				doc.documentElement.appendChild(doc.createCDATASection(payload));
			});
			var xml = new XMLSerializer().serializeToString(doc);
			assert.equal(xml, '<root/>');
			var reparsed = new DOMParser().parseFromString(xml, 'text/xml');
			assert.strictEqual(reparsed.getElementsByTagName('injected').length, 0);
		}
	},
	'parse path': {
		'parsing XML containing a CDATA section does not throw': function () {
			var doc = new DOMParser().parseFromString('<root><![CDATA[some data]]></root>', 'text/xml');
			assert.strictEqual(doc.documentElement.firstChild.nodeType, 4);
			assert.strictEqual(doc.documentElement.firstChild.data, 'some data');
		}
	}
}).run();
