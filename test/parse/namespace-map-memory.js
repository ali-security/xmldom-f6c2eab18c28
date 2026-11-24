var vows = require('vows');
var assert = require('assert');
var path = require('path');
var execFile = require('child_process').execFile;
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;

// CVE-2026-83615: appendElement in sax.js flat-copied the complete in-scope namespace map
// (_copy) for every element that declares a namespace prefix, and every copy stayed live on
// the parse stack until its element was closed. A document nesting N elements that each
// declare one new prefix therefore retained 1+2+...+N = O(N^2) map entries at the peak of
// DOMParser.parseFromString(), so a small, highly compressible document exhausted the heap.
// Each scope's map now inherits its parent's map through the prototype chain (one own entry
// per prefix declared at that element), so the peak stays O(N).
// https://github.com/xmldom/xmldom/security/advisories/GHSA-965w-775f-mr7g

// The peak is a transient allocation that GC releases once the parse ends, so it can not be
// sampled in-process: the guard parses in a child node process whose old space is capped.
// Unfixed, depth 2000 already exhausts a 128 MB old space; fixed, depth 5000 parses in a
// few MB, so the wide margin keeps the outcome stable across hosts.
var DEPTH = 5000;
var HEAP_MB = 128;
var TIMEOUT_MS = 120000;

// the repository root, whose package.json "main" is dom-parser.js
var LIB = path.resolve(__dirname, '..', '..');

var XML_NS = 'http://www.w3.org/XML/1998/namespace';

/**
 * Builds a `node -e` script that parses a document nesting `depth` elements, each declaring
 * and using one unique namespace prefix, and prints the namespace URI and the text of the
 * innermost element.
 */
function nsMapBombScript(depth) {
	return [
		'var DOMParser = require(' + JSON.stringify(LIB) + ').DOMParser;',
		'var open = "", close = "";',
		'for (var i = 0; i < ' + depth + '; i++) {',
		'  open += "<n" + i + ":a xmlns:n" + i + "=\\"urn:x:" + i + "\\">";',
		'  close = "</n" + i + ":a>" + close;',
		'}',
		'var doc = new DOMParser().parseFromString("<root>" + open + "leaf" + close + "</root>", "text/xml");',
		'var inner = doc.getElementsByTagName("n' + (depth - 1) + ':a")[0];',
		'process.stdout.write(inner.namespaceURI + " " + inner.firstChild.data);'
	].join('\n');
}

/**
 * Runs `script` in a child node process whose V8 old space is capped at `heapMb` megabytes
 * and passes `{err, stdout, stderr}` to `callback`: `err` is null iff the child exited 0.
 */
function runUnderHeapCap(script, heapMb, callback) {
	execFile(process.execPath, ['--max-old-space-size=' + heapMb, '-e', script],
		{ timeout: TIMEOUT_MS },
		function (err, stdout, stderr) {
			callback(null, { err: err, stdout: String(stdout), stderr: String(stderr) });
		});
}

function parseXml(source) {
	return new DOMParser().parseFromString(source, 'text/xml');
}

// a domBuilder that records the ended prefix mappings it receives
function recordingBuilder() {
	var builder = {endedPrefixes: [], errors: []};
	function noop() {}
	builder.startDocument = builder.endDocument = builder.startElement = builder.endElement = noop;
	builder.startPrefixMapping = builder.characters = builder.ignorableWhitespace = noop;
	builder.processingInstruction = builder.comment = noop;
	builder.startCDATA = builder.endCDATA = builder.startDTD = builder.endDTD = noop;
	builder.endPrefixMapping = function (prefix) {
		builder.endedPrefixes.push(prefix);
	};
	builder.warning = builder.error = builder.fatalError = function (msg) {
		builder.errors.push(msg);
	};
	return builder;
}

vows.describe('quadratic namespace-map memory during parse (GHSA-965w-775f-mr7g)').addBatch({
	'a deeply namespaced document parsed under a constrained heap': {
		topic: function () {
			runUnderHeapCap(nsMapBombScript(DEPTH), HEAP_MB, this.callback);
		},
		'completes within the heap budget': function (res) {
			assert.ok(!res.err, 'parsing ' + DEPTH + ' nested namespace scopes did not complete under a ' +
				HEAP_MB + ' MB old space (exit code ' + (res.err && res.err.code) + ', signal ' +
				(res.err && res.err.signal) + '): ' + res.stderr.slice(-500));
			assert.equal(res.stdout, 'urn:x:' + (DEPTH - 1) + ' leaf');
		}
	}
}).addBatch({
	'prefix declared once at the root resolves and serializes unchanged when used deeply nested': function () {
		var source =
			'<r xmlns:p="http://root.com">' +
			'<a><b><c><p:leaf p:attr="v"/></c></b></a>' +
			'<a2 xmlns:q="http://shadow.com"><q:mid><p:leaf2/></q:mid></a2>' +
			'</r>';
		var documentElement = parseXml(source).documentElement;

		// `p`, declared only at the root, resolves for elements and attributes many levels
		// down (inherited through the scope chain, not re-declared).
		var leaf = documentElement.getElementsByTagName('p:leaf')[0];
		assert.strictEqual(leaf.namespaceURI, 'http://root.com');
		assert.strictEqual(leaf.getAttributeNode('p:attr').namespaceURI, 'http://root.com');
		// A prefix declared at an inner scope resolves there while `p` still inherits.
		var mid = documentElement.getElementsByTagName('q:mid')[0];
		assert.strictEqual(mid.namespaceURI, 'http://shadow.com');
		assert.strictEqual(documentElement.getElementsByTagName('p:leaf2')[0].namespaceURI, 'http://root.com');

		// Behaviour-preserving: serialized output is byte-identical to the input.
		assert.strictEqual(new XMLSerializer().serializeToString(documentElement), source);
	},
	'a prefix redeclared at an inner scope shadows the outer binding inside that scope only': function () {
		var source =
			'<r xmlns:p="urn:outer">' +
			'<a xmlns:p="urn:inner" xmlns:q="urn:q"><p:x p:y="1"/><q:w/></a>' +
			'<p:z p:y="2"/>' +
			'</r>';
		var root = parseXml(source).documentElement;
		var x = root.getElementsByTagName('p:x')[0];
		assert.strictEqual(x.namespaceURI, 'urn:inner');
		assert.strictEqual(x.getAttributeNode('p:y').namespaceURI, 'urn:inner');
		assert.strictEqual(root.getElementsByTagName('q:w')[0].namespaceURI, 'urn:q');
		// the inner declarations did not leak into the parent scope once `a` was closed
		var z = root.getElementsByTagName('p:z')[0];
		assert.strictEqual(z.namespaceURI, 'urn:outer');
		assert.strictEqual(z.getAttributeNode('p:y').namespaceURI, 'urn:outer');
		assert.strictEqual(root.lookupNamespaceURI('p'), 'urn:outer');
	},
	'the default namespace is inherited through scopes declaring other prefixes': function () {
		var root = parseXml(
			'<r xmlns="urn:d"><a xmlns:p="urn:p"><b/><c xmlns=""><d/></c><e/></a><f/></r>'
		).documentElement;
		assert.strictEqual(root.namespaceURI, 'urn:d');
		assert.strictEqual(root.getElementsByTagName('a')[0].namespaceURI, 'urn:d');
		assert.strictEqual(root.getElementsByTagName('b')[0].namespaceURI, 'urn:d');
		// xmlns="" undeclares the default namespace for c and its descendants only
		assert.ok(!root.getElementsByTagName('c')[0].namespaceURI);
		assert.ok(!root.getElementsByTagName('d')[0].namespaceURI);
		assert.strictEqual(root.getElementsByTagName('e')[0].namespaceURI, 'urn:d');
		assert.strictEqual(root.getElementsByTagName('f')[0].namespaceURI, 'urn:d');
	},
	'every ancestor prefix resolves through many nested scopes': function () {
		var depth = 200;
		var open = '';
		var close = '';
		for (var i = 0; i < depth; i++) {
			open += '<n' + i + ':a xmlns:n' + i + '="urn:x:' + i + '">';
			close = '</n' + i + ':a>' + close;
		}
		var attrs = '';
		for (i = 0; i < depth; i += 37) {
			attrs += ' n' + i + ':attr="' + i + '"';
		}
		var source = '<root>' + open + '<leaf xml:lang="en"' + attrs + '/>' + close + '</root>';
		var root = parseXml(source).documentElement;
		var leaf = root.getElementsByTagName('leaf')[0];
		assert.ok(!leaf.namespaceURI);
		assert.strictEqual(leaf.getAttributeNode('xml:lang').namespaceURI, XML_NS);
		for (i = 0; i < depth; i += 37) {
			assert.strictEqual(leaf.getAttributeNode('n' + i + ':attr').namespaceURI, 'urn:x:' + i);
		}
		for (i = 0; i < depth; i++) {
			assert.strictEqual(root.getElementsByTagName('n' + i + ':a')[0].namespaceURI, 'urn:x:' + i);
		}
		assert.strictEqual(new XMLSerializer().serializeToString(root), source);
	},
	'endPrefixMapping is only reported for the prefixes declared at each element': function () {
		var builder = recordingBuilder();
		new DOMParser({domBuilder: builder}).parseFromString(
			'<r xmlns:a="urn:a"><x xmlns:b="urn:b" xmlns:c="urn:c"><y xmlns:d="urn:d"/><z/></x></r>',
			'text/xml'
		);
		assert.deepEqual(builder.errors, []);
		// d ends with the self-closed y, b and c with the end tag of x, a with the end tag of r;
		// no inherited prefix (or the default xml binding) is reported again
		assert.deepEqual(builder.endedPrefixes.slice(0, 1), ['d']);
		assert.deepEqual(builder.endedPrefixes.slice(1, 3).sort(), ['b', 'c']);
		assert.deepEqual(builder.endedPrefixes.slice(3), ['a']);
	}
}).run();
