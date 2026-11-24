var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var DOMImplementation = require('xmldom/dom').DOMImplementation;

// CVE-2026-83614: two independent quadratic paths.
//  - Finding A (sax.js): parseElementStartPart scanned a malformed tag name on to the next
//    `>` (or `/`, or the end of input) before rejecting it, and parse() recovers one
//    character at a time, so a document with many `<` inside a malformed tag re-scanned to
//    the distant terminator once per `<`: O(n^2). A `<` where a tag name is expected is now
//    rejected right away, which keeps every recovery step bounded.
//  - Finding B (dom.js): Node#normalize() merged a run of K adjacent text nodes with one
//    removeChild (an O(K) re-index of childNodes) and one appendData (an O(K) string
//    rebuild) per sibling: O(K^2). Each run is now merged in a single pass, and the child
//    list is re-indexed once per parent, so many short runs split by elements stay linear
//    too. The recovery above emits one text node per recovered character, and
//    DOMHandler.endDocument normalizes the parsed document, so this is reachable from
//    parseFromString() as well as from a direct normalize() call on a DOM built with
//    createTextNode + appendChild.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-93r5-fhx6-vmg9

// Every attack is timed against a benign input of the same scale: the same number of
// children under one parent, but no adjacent text nodes and no malformed tag. A growth ratio
// over a size increase is blurred on the old V8 of the Node versions this suite runs on
// (building many siblings is itself mildly superlinear there), while the attack/benign ratio
// is not: with the fix an attack costs a small constant factor of the benign input; without
// it the quadratic paths make it hundreds of times slower at this size.
var N = 16000;
var ATTACK_RATIO_MAX = 20;
var RUNS = 5;

function repeat(str, times) {
	return new Array(times + 1).join(str);
}

function elapsedMs(t) {
	var d = process.hrtime(t);
	return d[0] * 1e3 + d[1] / 1e6;
}

/**
 * Returns the fastest wall-clock (ms) of `runs` executions of `fn`: the minimum is the
 * least noise-inflated sample, so a ratio built from two such measurements is stable
 * across fast and slow hosts.
 */
function fastestMs(fn, runs) {
	var best = Infinity;
	for (var k = 0; k < runs; k++) {
		var t = process.hrtime();
		fn();
		var ms = elapsedMs(t);
		if (ms < best) {
			best = ms;
		}
	}
	return best;
}

function assertAttackRatio(what, attackMs, benignMs) {
	var ratio = attackMs / Math.max(benignMs, 1);
	console.log(what + ': attack ' + attackMs.toFixed(1) + 'ms, benign ' + benignMs.toFixed(1) +
		'ms (' + ratio.toFixed(1) + 'x)');
	assert.ok(ratio < ATTACK_RATIO_MAX,
		what + ' took ' + ratio.toFixed(1) + 'x the benign input (' + attackMs.toFixed(1) +
		'ms vs ' + benignMs.toFixed(1) + 'ms), expected < ' + ATTACK_RATIO_MAX + 'x');
}

// A silent errorHandler keeps the recovery reports of the malformed input off the console;
// parsing behaviour is unchanged.
function silent() {}

function parseSilently(source, mimeType) {
	try {
		return new DOMParser({errorHandler: silent}).parseFromString(source, mimeType);
	} catch (e) {
		// default recovery reports (does not throw); timing is what matters
		return null;
	}
}

/**
 * Parses `source` and collects what the errorHandler reports, per level.
 */
function parseCollecting(source, mimeType) {
	var reported = {warning: [], error: [], fatalError: []};
	var doc = new DOMParser({
		errorHandler: {
			warning: function (msg) { reported.warning.push(msg); },
			error: function (msg) { reported.error.push(msg); },
			fatalError: function (msg) { reported.fatalError.push(msg); }
		}
	}).parseFromString(source, mimeType);
	return {doc: doc, reported: reported};
}

function assertParseNotSlowerThanBenign(what, attack, benign, mimeType) {
	var benignMs = fastestMs(function () { parseSilently(benign, mimeType); }, RUNS);
	var attackMs = fastestMs(function () { parseSilently(attack, mimeType); }, RUNS);
	assertAttackRatio(what, attackMs, benignMs);
}

// every interior `<` starts a malformed tag whose name runs on to the distant `</r>`
function malformedTagBomb(n) {
	return '<r>' + repeat('a<', n) + '</r>';
}

// every interior `<` starts a malformed tag whose name runs on to the distant `>`
function lessThanRunBomb(n) {
	return '<r><a' + repeat('<', n) + '></r>';
}

// `a<>` recovers to three adjacent single-character text nodes and keeps each re-scan short,
// so the cost isolates to the normalize() that endDocument runs
function adjacentTextBomb(n) {
	return '<r>' + repeat('a<>', n) + '</r>';
}

// the same, as n short runs of adjacent text nodes split by an element
function shortTextRunsBomb(n) {
	return '<r>' + repeat('a<><b/>', n) + '</r>';
}

// n text nodes alternating with n empty elements: as many children as the bombs, but
// nothing to merge and no malformed tag
function benignDocument(n) {
	return '<r>' + repeat('a<b/>', n) + '</r>';
}

function newDocument() {
	return new DOMImplementation().createDocument(null, 'root');
}

// `pattern` lists the children appended to the root per unit: 't' a text node, 'e' an element
function buildRoot(pattern, units) {
	var doc = newDocument();
	var root = doc.documentElement;
	for (var i = 0; i < units; i++) {
		for (var j = 0; j < pattern.length; j++) {
			root.appendChild(pattern.charAt(j) === 't' ? doc.createTextNode('x') : doc.createElement('e'));
		}
	}
	return root;
}

/**
 * Returns the fastest time of `runs` normalize() calls, each on a fresh root built (outside
 * the timed section) from `pattern` repeated `units` times, which leaves `expectedLength`
 * children.
 */
function fastestNormalizeMs(pattern, units, expectedLength, runs) {
	var best = Infinity;
	for (var r = 0; r < runs; r++) {
		var root = buildRoot(pattern, units);
		var t = process.hrtime();
		root.normalize();
		var ms = elapsedMs(t);
		assert.equal(root.childNodes.length, expectedLength);
		if (ms < best) {
			best = ms;
		}
	}
	return best;
}

vows.describe('quadratic malformed-tag recovery re-scan and normalize (GHSA-93r5-fhx6-vmg9)').addBatch({
	'Finding A: a malformed tag full of `<` parses as fast as a benign document': function () {
		assertParseNotSlowerThanBenign('Finding A text/xml parse',
			malformedTagBomb(N), benignDocument(N), 'text/xml');
	},
	'Finding A: the same input parses as fast as a benign document as text/html': function () {
		assertParseNotSlowerThanBenign('Finding A text/html parse',
			malformedTagBomb(N), benignDocument(N), 'text/html');
	},
	'Finding A: a run of `<` inside a tag parses as fast as a benign document': function () {
		assertParseNotSlowerThanBenign('Finding A `<` run text/xml parse',
			lessThanRunBomb(N), benignDocument(N), 'text/xml');
	},
	'Finding B: parse-triggered adjacent-text normalize is as fast as a benign document': function () {
		assertParseNotSlowerThanBenign('Finding B text/html parse',
			adjacentTextBomb(N), benignDocument(N), 'text/html');
	},
	'Finding B: parse-triggered normalize of many short text runs is as fast as a benign document': function () {
		assertParseNotSlowerThanBenign('Finding B short runs text/html parse',
			shortTextRunsBomb(N), benignDocument(N), 'text/html');
	},
	'Finding B: programmatic normalize of one long text run is as fast as a benign tree': function () {
		var benignMs = fastestNormalizeMs('te', N / 2, N, RUNS);
		var attackMs = fastestNormalizeMs('t', N, 1, RUNS);
		assertAttackRatio('Finding B programmatic normalize() of one run', attackMs, benignMs);
	},
	'Finding B: programmatic normalize of many short text runs is as fast as a benign tree': function () {
		var benignMs = fastestNormalizeMs('tee', N, 3 * N, RUNS);
		var attackMs = fastestNormalizeMs('tte', N, 2 * N, RUNS);
		assertAttackRatio('Finding B programmatic normalize() of short runs', attackMs, benignMs);
	}
}).addBatch({
	'the malformed-tag bomb still recovers to the same text': function () {
		var doc = parseSilently(malformedTagBomb(1000), 'text/xml');
		var root = doc.documentElement;
		assert.equal(root.tagName, 'r');
		assert.equal(root.childNodes.length, 1);
		assert.equal(root.firstChild.data, repeat('a<', 1000));
	},
	'the adjacent-text bomb still recovers to the same text': function () {
		var doc = parseSilently(adjacentTextBomb(1000), 'text/html');
		var root = doc.documentElement;
		assert.equal(root.tagName, 'r');
		assert.equal(root.childNodes.length, 1);
		assert.equal(root.firstChild.data, repeat('a<>', 1000));
	},
	'the `<` run bomb still recovers to the same text': function () {
		var doc = parseSilently(lessThanRunBomb(1000), 'text/xml');
		var root = doc.documentElement;
		assert.equal(root.tagName, 'r');
		assert.equal(root.childNodes.length, 1);
		assert.equal(root.firstChild.data, '<a' + repeat('<', 1000) + '>');
	},
	'the short text runs bomb merges each run and keeps the elements between them': function () {
		var doc = parseSilently(shortTextRunsBomb(1000), 'text/html');
		var root = doc.documentElement;
		assert.equal(root.childNodes.length, 2000);
		for (var i = 0; i < 2000; i += 2) {
			var text = root.childNodes.item(i);
			var el = root.childNodes.item(i + 1);
			assert.equal(text.data, 'a<>');
			assert.equal(el.tagName, 'b');
			assert.strictEqual(text.nextSibling, el);
			assert.strictEqual(el.previousSibling, text);
		}
		assert.strictEqual(root.childNodes.item(2000), null);
		assert.strictEqual(root.lastChild, root.childNodes.item(1999));
	},
	'a `<` where a tag name is expected is reported and recovers to the same DOM': function () {
		var result = parseCollecting('<r>a<b</r>', 'text/xml');
		// the DOM is byte-identical to the previous recovery, only the error text changed
		assert.equal(result.doc.toString(), '<r>a&lt;b</r>');
		var errors = result.reported.error.join('\n');
		assert.ok(/unexpected < in tag name: b(?!<)/.test(errors), errors);
		assert.ok(!/invalid tagName/.test(errors), errors);
	},
	'a `<` right after a tag name is reported with the raw candidate': function () {
		var result = parseCollecting('<a<b/>', 'text/xml');
		var errors = result.reported.error.join('\n');
		assert.ok(/element parse error: Error: unexpected < in tag name: a(?!<)/.test(errors), errors);
		assert.equal(result.doc.documentElement.tagName, 'b');
	},
	'well-formed documents parse without the new error': function () {
		var sources = [
			'<a><b/></a>',
			'<a><b></b>text<c x="1"/></a>',
			'<r a="1&lt;2" b=\'x<y\'><b/>t</r>',
			'<?xml version="1.0"?><r><!-- c --><![CDATA[<x>]]><p:e xmlns:p="urn:p"/></r>',
			benignDocument(3)
		];
		sources.forEach(function (source) {
			var result = parseCollecting(source, 'text/xml');
			var all = result.reported.warning.concat(result.reported.error, result.reported.fatalError);
			assert.equal(all.length, 0, source + ': ' + all.join('\n'));
		});
		var doc = parseCollecting('<r a="1&lt;2" b=\'x<y\'><b/>t</r>', 'text/xml').doc;
		assert.equal(doc.documentElement.getAttribute('a'), '1<2');
		assert.equal(doc.documentElement.getAttribute('b'), 'x<y');
		assert.equal(doc.documentElement.firstChild.tagName, 'b');
		assert.equal(doc.toString(), '<r a="1&lt;2" b="x&lt;y"><b/>t</r>');
		// the timing baseline is benign: 2n children, nothing merged
		var benign = parseCollecting(benignDocument(1000), 'text/xml').doc.documentElement;
		assert.equal(benign.childNodes.length, 2000);
		assert.equal(benign.toString(), benignDocument(1000));
	}
}).addBatch({
	'normalize merges a run of adjacent text nodes into the first, which survives with the concatenated data': function () {
		var d = newDocument();
		var root = d.documentElement;
		var first = d.createTextNode('a');
		var second = d.createTextNode('b');
		var third = d.createTextNode('c');
		root.appendChild(first);
		root.appendChild(second);
		root.appendChild(third);

		root.normalize();

		assert.equal(root.childNodes.length, 1);
		assert.strictEqual(root.firstChild, first); // the first node survives (identity)
		assert.strictEqual(root.childNodes.item(0), first);
		assert.strictEqual(root.childNodes.item(1), null);
		assert.strictEqual(root.childNodes.item(2), null);
		assert.strictEqual(root.childNodes[2], undefined);
		assert.equal(first.data, 'abc');
		assert.equal(first.nodeValue, 'abc');
		assert.equal(first.length, 3);
		assert.strictEqual(root.lastChild, first);
		assert.strictEqual(first.nextSibling, null);
		assert.strictEqual(first.previousSibling, null);
		// the merged-away nodes are detached
		[second, third].forEach(function (removed) {
			assert.strictEqual(removed.parentNode, null);
			assert.strictEqual(removed.previousSibling, null);
			assert.strictEqual(removed.nextSibling, null);
		});
		assert.equal(root.toString(), '<root>abc</root>');
	},
	'normalize merges only within a run, leaving non-text nodes and their boundaries intact': function () {
		var d = newDocument();
		var root = d.documentElement;
		var t1 = d.createTextNode('a');
		root.appendChild(t1);
		root.appendChild(d.createTextNode('b'));
		var el = d.createElement('e');
		root.appendChild(el);
		var t2 = d.createTextNode('c');
		root.appendChild(t2);
		root.appendChild(d.createTextNode('d'));

		root.normalize();

		assert.equal(root.childNodes.length, 3);
		assert.strictEqual(root.firstChild, t1);
		assert.equal(t1.data, 'ab');
		assert.strictEqual(root.childNodes.item(0), t1);
		assert.strictEqual(root.childNodes.item(1), el);
		assert.strictEqual(root.childNodes.item(2), t2);
		assert.strictEqual(root.childNodes.item(3), null);
		assert.strictEqual(root.lastChild, t2);
		assert.equal(t2.data, 'cd');
		assert.strictEqual(t1.nextSibling, el);
		assert.strictEqual(el.previousSibling, t1);
		assert.strictEqual(el.nextSibling, t2);
		assert.strictEqual(t2.previousSibling, el);
		assert.strictEqual(t2.nextSibling, null);
		assert.equal(root.toString(), '<root>ab<e/>cd</root>');
	},
	'normalize merges text runs in nested elements and keeps a live child list current': function () {
		var d = newDocument();
		var root = d.documentElement;
		var inner = d.createElement('i');
		root.appendChild(d.createTextNode('1'));
		root.appendChild(inner);
		inner.appendChild(d.createTextNode('2'));
		inner.appendChild(d.createTextNode('3'));
		inner.appendChild(d.createTextNode('4'));
		var elements = root.getElementsByTagName('i');
		assert.equal(elements.length, 1);

		d.normalize();

		assert.equal(root.childNodes.length, 2);
		assert.equal(inner.childNodes.length, 1);
		assert.equal(inner.firstChild.data, '234');
		assert.strictEqual(inner.lastChild, inner.firstChild);
		assert.equal(elements.length, 1);
		assert.equal(root.toString(), '<root>1<i>234</i></root>');
		// the merged node stays editable through the DOM API
		inner.appendChild(d.createTextNode('5'));
		assert.equal(inner.childNodes.length, 2);
		inner.normalize();
		assert.equal(inner.childNodes.length, 1);
		assert.equal(inner.firstChild.data, '2345');
		inner.removeChild(inner.firstChild);
		assert.equal(inner.childNodes.length, 0);
		assert.strictEqual(inner.firstChild, null);
		assert.strictEqual(inner.lastChild, null);
	}
}).run();
