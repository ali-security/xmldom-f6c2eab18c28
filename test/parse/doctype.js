var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var DOMImplementation = require('xmldom').DOMImplementation;
var XMLSerializer = require('xmldom').XMLSerializer;
var getTestParser = require('../get-test-parser').getTestParser;

// CVE-2021-21366: the public and system identifiers of a DOCTYPE are provided without
// their quotes by DocumentType.publicId/systemId, so they have to be quoted again when
// serializing, with a quote they don't contain: otherwise parsing and serializing a
// document changes its syntax, e.g. an identifier becomes an internal subset.

function parseDoctype(source, mimeType) {
	var p = getTestParser();
	var doc = p.parser.parseFromString(source, mimeType || 'text/xml');
	assert.deepEqual(p.errors, {}, 'unexpected errors: ' + JSON.stringify(p.errors));
	return doc;
}

function serialize(node) {
	return new XMLSerializer().serializeToString(node);
}

function roundTrip(source) {
	return serialize(parseDoctype(source));
}

// Every identifier of a serialized DOCTYPE has to be one complete literal and the DOCTYPE
// has to end right after it, otherwise the identifier ended up as markup.
var LITERAL = '(?:\'[^\']*\'|"[^"]*")';
var PUBLIC_DOCTYPE = new RegExp('^<!DOCTYPE x PUBLIC ' + LITERAL + '(?: ' + LITERAL + ')?>');
var SYSTEM_DOCTYPE = new RegExp('^<!DOCTYPE x SYSTEM ' + LITERAL + '>');

var XHTML_PUBID = '-//W3C//DTD XHTML 1.0 Strict//EN';
var XHTML_SYSID = 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd';
var XHTML_DOCTYPE = '<!DOCTYPE html PUBLIC "' + XHTML_PUBID + '" "' + XHTML_SYSID + '">';

// A literal that closes the double quotes 0.1.31 put around it when serializing,
// to add an internal subset to the DOCTYPE.
var INJECTED = '\'"[<!ENTITY e "x">]\'';
var INJECTED_VALUE = '"[<!ENTITY e "x">]';
var INJECTED_SPACED = '\'" [<!ENTITY xxe SYSTEM "file:///etc/passwd">] "\'';

vows.describe('doctype').addBatch({
	'PUBLIC and SYSTEM ids are provided without their quotes': function () {
		['text/xml', 'text/html'].forEach(function (mimeType) {
			var doctype = parseDoctype(XHTML_DOCTYPE + '<html/>', mimeType).firstChild;
			assert.equal(doctype.name, 'html');
			assert.equal(doctype.publicId, XHTML_PUBID);
			assert.equal(doctype.systemId, XHTML_SYSID);
		});
		var doctype = parseDoctype('<!DOCTYPE x PUBLIC \'pub\' \'sys\'><x/>').firstChild;
		assert.equal(doctype.publicId, 'pub');
		assert.equal(doctype.systemId, 'sys');
	},
	'SYSTEM id without PUBLIC id': function () {
		var doctype = parseDoctype('<!DOCTYPE x SYSTEM "x.dtd"><x/>').firstChild;
		assert.equal(doctype.name, 'x');
		assert.equal(doctype.systemId, 'x.dtd');
		assert.ok(!doctype.publicId, 'publicId: ' + doctype.publicId);
	},
	'PUBLIC id without SYSTEM id': function () {
		var doctype = parseDoctype('<!DOCTYPE x PUBLIC "pub"><x/>').firstChild;
		assert.equal(doctype.name, 'x');
		assert.equal(doctype.publicId, 'pub');
		assert.ok(!doctype.systemId, 'systemId: ' + doctype.systemId);
	},
	'DOCTYPE without ids': function () {
		var doctype = parseDoctype('<!DOCTYPE x><x/>').firstChild;
		assert.equal(doctype.name, 'x');
		assert.ok(!doctype.publicId, 'publicId: ' + doctype.publicId);
		assert.ok(!doctype.systemId, 'systemId: ' + doctype.systemId);
	},
	'ids with mixed quotes': function () {
		['SYSTEM', 'PUBLIC'].forEach(function (idType) {
			[
				['outer single', '<!DOCTYPE x ' + idType + ' \'"\'><X/>', '"'],
				['outer double', '<!DOCTYPE x ' + idType + ' "\'"><X/>', '\''],
				['outer single', '<!DOCTYPE x ' + idType + ' \'a"b\'><X/>', 'a"b'],
				['outer double', '<!DOCTYPE x ' + idType + ' "a\'b"><X/>', 'a\'b']
			].forEach(function (sample) {
				var doctype = parseDoctype(sample[1]).firstChild;
				var message = idType + ' ' + sample[0] + ': ' + sample[1];
				assert.equal(doctype.name, 'x', message);
				if (idType === 'SYSTEM') {
					assert.equal(doctype.systemId, sample[2], message);
					assert.ok(!doctype.publicId, message + ' publicId: ' + doctype.publicId);
				} else {
					assert.equal(doctype.publicId, sample[2], message);
					assert.ok(!doctype.systemId, message + ' systemId: ' + doctype.systemId);
				}
			});
		});
	},
	'serializing keeps PUBLIC and SYSTEM ids': function () {
		assert.equal(roundTrip(XHTML_DOCTYPE + '<html/>'), XHTML_DOCTYPE + '<html/>');
		var source = '<!DOCTYPE x PUBLIC "-//W3C//DTD HTML 4.01//EN"><x/>';
		assert.equal(roundTrip(source), source);
		source = '<!DOCTYPE x SYSTEM "x.dtd"><x/>';
		assert.equal(roundTrip(source), source);
		// as before, ids are serialized with double quotes when they don't contain any
		assert.equal(roundTrip('<!DOCTYPE x PUBLIC \'pub\' \'sys\'><x/>'), '<!DOCTYPE x PUBLIC "pub" "sys"><x/>');
	},
	'serializing keeps mixed quotes in ids': function () {
		var source = '<!DOCTYPE x SYSTEM \'a"b\'><x/>';
		assert.equal(roundTrip(source), source);
		source = '<!DOCTYPE x PUBLIC \'"\' "\'"><x/>';
		assert.equal(roundTrip(source), source);
		source = '<!DOCTYPE x PUBLIC "a\'b" \'a"b\'><x/>';
		assert.equal(roundTrip(source), source);
	},
	'SYSTEM id can not inject an internal subset when serialized': function () {
		[INJECTED, INJECTED_SPACED].forEach(function (literal) {
			var source = '<!DOCTYPE x SYSTEM ' + literal + '><x/>';
			var serialized = roundTrip(source);
			assert.equal(serialized, source);
			assert.ok(SYSTEM_DOCTYPE.test(serialized), serialized);
			assert.equal(roundTrip(serialized), serialized);
		});
		assert.equal(parseDoctype('<!DOCTYPE x SYSTEM ' + INJECTED + '><x/>').firstChild.systemId, INJECTED_VALUE);
	},
	'PUBLIC id can not inject an internal subset when serialized': function () {
		[INJECTED, INJECTED_SPACED].forEach(function (literal) {
			var source = '<!DOCTYPE x PUBLIC ' + literal + ' "sys"><x/>';
			var serialized = roundTrip(source);
			assert.equal(serialized, source);
			assert.ok(PUBLIC_DOCTYPE.test(serialized), serialized);
			assert.equal(roundTrip(serialized), serialized);
		});
		assert.equal(parseDoctype('<!DOCTYPE x PUBLIC ' + INJECTED + '><x/>').firstChild.publicId, INJECTED_VALUE);
	},
	'SYSTEM id after PUBLIC id can not inject an internal subset when serialized': function () {
		[INJECTED, INJECTED_SPACED].forEach(function (literal) {
			var source = '<!DOCTYPE x PUBLIC "pub" ' + literal + '><x/>';
			var serialized = roundTrip(source);
			assert.equal(serialized, source);
			assert.ok(PUBLIC_DOCTYPE.test(serialized), serialized);
			assert.equal(roundTrip(serialized), serialized);
		});
	},
	'ids containing both quotes are serialized as one literal': function () {
		var impl = new DOMImplementation();
		var doctype = impl.createDocumentType('x', 'p"\'[<!ENTITY e "x">]', 's"\'[<!ENTITY e "x">]');
		var serialized = serialize(impl.createDocument(null, 'x', doctype));
		assert.ok(PUBLIC_DOCTYPE.test(serialized), serialized);
		assert.equal(serialized, '<!DOCTYPE x PUBLIC "p%22\'[<!ENTITY e %22x%22>]" "s%22\'[<!ENTITY e %22x%22>]"><x/>');
		doctype = impl.createDocumentType('x', null, 's"\'[<!ENTITY e "x">]');
		serialized = serialize(impl.createDocument(null, 'x', doctype));
		assert.ok(SYSTEM_DOCTYPE.test(serialized), serialized);
		assert.equal(serialized, '<!DOCTYPE x SYSTEM "s%22\'[<!ENTITY e %22x%22>]"><x/>');
	}
}).run();
