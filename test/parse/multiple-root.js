var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;

// CVE-2022-39353: xmldom parsed XML that is not well-formed because it contains
// multiple top level elements, and added all of them to the childNodes of the
// Document without reporting an error. The DOMHandler inserts every node with
// appendChild, which now rejects a second root element (and a doctype after the
// root element), so the parser reports an error and keeps a single root.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-crh6-fp67-6883

var ONLY_ONE_ELEMENT = /^\[xmldom error\]\telement parse error: Error: Hierarchy request error: Only one element can be added and only after doctype/;

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

function childrenOfType(node, nodeType) {
	var found = [];
	for (var child = node.firstChild; child; child = child.nextSibling) {
		if (child.nodeType === nodeType) {
			found.push(child);
		}
	}
	return found;
}

function assertSingleRoot(doc, tagName) {
	var elements = childrenOfType(doc, 1);
	assert.strictEqual(elements.length, 1, 'element children of the document: ' + elements.length);
	assert.strictEqual(doc.documentElement, elements[0]);
	assert.equal(doc.documentElement.tagName, tagName);
	var childNodeElements = 0;
	for (var i = 0; i < doc.childNodes.length; i++) {
		if (doc.childNodes.item(i).nodeType === 1) {
			childNodeElements++;
		}
	}
	assert.strictEqual(childNodeElements, 1, 'element entries in document.childNodes: ' + childNodeElements);
}

function assertErrors(errors, pattern) {
	assert.ok(errors.error && errors.error.length > 0, 'expected an error to be reported');
	assert.ok(pattern.test(errors.error[0]), 'unexpected error: ' + errors.error[0]);
	assert.strictEqual(errors.fatalError, undefined);
}

vows.describe('multiple root elements (not well-formed)').addBatch({
	'a second self-closing root element is reported and not added': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString('<doc/><doc/>\n', 'text/xml');
		assertErrors(p.errors, ONLY_ONE_ELEMENT);
		assertSingleRoot(doc, 'doc');
		assert.equal(new XMLSerializer().serializeToString(doc), '<doc/>&lt;doc/>\n');
	},
	'a second root element on the next line is reported and not added': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString('<doc></doc>\n<doc></doc>\n', 'text/xml');
		assertErrors(p.errors, ONLY_ONE_ELEMENT);
		assertSingleRoot(doc, 'doc');
		assert.equal(doc.toString(), '<doc/>\n&lt;doc>');
	},
	'a second root element with children is not added': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString('<root><a/></root><root2><b/></root2>', 'text/xml');
		assertErrors(p.errors, ONLY_ONE_ELEMENT);
		assertSingleRoot(doc, 'root');
		assert.strictEqual(doc.getElementsByTagName('root2').length, 0);
		assert.strictEqual(doc.getElementsByTagName('b').length, 0);
		assert.strictEqual(doc.getElementsByTagName('a').length, 1);
	},
	'a doctype after the root element is reported and not added': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString('<root/>\n<!DOCTYPE root>', 'text/xml');
		assertErrors(p.errors, /Hierarchy request error: Doctype can not be appended since element is present/);
		assertSingleRoot(doc, 'root');
		assert.strictEqual(childrenOfType(doc, 10).length, 0);
	}
}).addBatch({
	'a doctype before the root element is still accepted': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString('<!DOCTYPE root>\n<root/>', 'text/xml');
		assert.strictEqual(p.errors.error, undefined);
		assert.strictEqual(doc.firstChild.nodeType, 10);
		assertSingleRoot(doc, 'root');
	},
	'processing instructions, comments and whitespace around the root are still accepted': function () {
		var p = getTestParser();
		var source = '<?xml version="1.0"?>\n<!--test-->\n<xml/>\n<!--after-->';
		var doc = p.parser.parseFromString(source, 'text/xml');
		assert.strictEqual(p.errors.error, undefined);
		assertSingleRoot(doc, 'xml');
		assert.equal(new XMLSerializer().serializeToString(doc), source);
	},
	'sibling elements inside the root element are still accepted': function () {
		var p = getTestParser();
		var doc = p.parser.parseFromString('<xml><book></book><title>Harry Potter</title></xml>', 'text/xml');
		assert.strictEqual(p.errors.error, undefined);
		assert.equal(doc.toString(), '<xml><book/><title>Harry Potter</title></xml>');
	}
}).run();
