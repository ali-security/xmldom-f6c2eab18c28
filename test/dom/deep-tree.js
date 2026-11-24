var vows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
var DOMImplementation = require('xmldom/dom').DOMImplementation;

// CVE-2026-41673: every DOM tree traversal recursed once per nesting level, so on a deeply
// nested but well-formed document (the SAX parser itself is iterative) normalize(),
// serializeToString()/toString(), getElementsByTagName(NS)(), getElementById(),
// cloneNode(true), importNode(node, true) or the textContent getter crashed the process
// with "RangeError: Maximum call stack size exceeded". DOMParser.parseFromString() crashed
// as well, since it normalizes the document when parsing ends.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-2v35-w6hq-6mfw

// Far beyond the depth at which a recursive function overflows the default call stack
// (the first vow asserts that), so re-introducing any recursive tree walk breaks these vows.
var DEEP_TREE_DEPTH = 100000;

var HTML_NS = 'http://www.w3.org/1999/xhtml';

function repeat(str, times) {
	return new Array(times + 1).join(str);
}

// what the tree built by createDeepTree() serializes to
var DEEP_TREE_XML = '<root>' + repeat('<n>', DEEP_TREE_DEPTH) + 'deep text' + repeat('</n>', DEEP_TREE_DEPTH) + '</root>';

/**
 * Builds <root><n><n>...<n>deep text</n>...</n></n></root> through the DOM API, with
 * DEEP_TREE_DEPTH nested `n` elements; the innermost one holds two adjacent text nodes.
 */
function createDeepTree() {
	var doc = new DOMImplementation().createDocument(null, 'root');
	var current = doc.documentElement;
	for (var i = 0; i < DEEP_TREE_DEPTH; i++) {
		var child = doc.createElement('n');
		current.appendChild(child);
		current = child;
	}
	current.appendChild(doc.createTextNode('deep '));
	current.appendChild(doc.createTextNode('text'));
	return { doc: doc, root: doc.documentElement, innermost: current };
}

function parseXml(source) {
	return new DOMParser().parseFromString(source, 'text/xml');
}

// fails with the RangeError (and not just an assertion message) if fn overflows the stack
function noStackOverflow(fn) {
	var result;
	assert.doesNotThrow(function () {
		result = fn();
	}, RangeError);
	return result;
}

function tagNames(nodeList) {
	var names = [];
	for (var i = 0; i < nodeList.length; i++) {
		names.push(nodeList.item(i).tagName);
	}
	return names.join(',');
}

vows.describe('Deep tree stack overflow guard (GHSA-2v35-w6hq-6mfw)').addBatch({
	'a recursive function overflows the call stack within DEEP_TREE_DEPTH frames': function () {
		function throwsAtLevel(lvl) {
			var nextLvl = (lvl || 0) + 1;
			try {
				return throwsAtLevel(nextLvl);
			} catch (e) {
				return nextLvl;
			}
		}
		var level = throwsAtLevel();
		assert.ok(level <= DEEP_TREE_DEPTH, 'call stack overflowed only at level ' + level);
	}
}).addBatch({
	// a DEEP_TREE_DEPTH deep tree built through the DOM API
	'getElementsByTagName': function () {
		var tree = createDeepTree();
		var list = noStackOverflow(function () {
			return tree.root.getElementsByTagName('n');
		});
		assert.strictEqual(list.length, DEEP_TREE_DEPTH);
		assert.strictEqual(list.item(DEEP_TREE_DEPTH - 1), tree.innermost);
	},
	'getElementsByTagNameNS': function () {
		var tree = createDeepTree();
		var list = noStackOverflow(function () {
			return tree.root.getElementsByTagNameNS('*', '*');
		});
		assert.strictEqual(list.length, DEEP_TREE_DEPTH);
	},
	'getElementById': function () {
		var tree = createDeepTree();
		tree.innermost.setAttribute('id', 'deepest');
		var found = noStackOverflow(function () {
			return tree.doc.getElementById('deepest');
		});
		assert.strictEqual(found, tree.innermost);
	},
	'textContent': function () {
		var tree = createDeepTree();
		var text = noStackOverflow(function () {
			return tree.root.textContent;
		});
		assert.strictEqual(text, 'deep text');
	},
	'XMLSerializer.serializeToString': function () {
		var tree = createDeepTree();
		var xml = noStackOverflow(function () {
			return new XMLSerializer().serializeToString(tree.doc);
		});
		assert.strictEqual(xml, DEEP_TREE_XML);
	},
	'Node.toString': function () {
		var tree = createDeepTree();
		var xml = noStackOverflow(function () {
			return tree.root.toString();
		});
		assert.strictEqual(xml, DEEP_TREE_XML);
	},
	'NodeList.toString': function () {
		var tree = createDeepTree();
		var xml = noStackOverflow(function () {
			return tree.doc.childNodes.toString();
		});
		assert.strictEqual(xml, DEEP_TREE_XML);
	},
	'cloneNode(true)': function () {
		var tree = createDeepTree();
		var clone = noStackOverflow(function () {
			return tree.root.cloneNode(true);
		});
		assert.notStrictEqual(clone, tree.root);
		assert.strictEqual(clone.toString(), DEEP_TREE_XML);
	},
	'importNode(node, true)': function () {
		var tree = createDeepTree();
		var destDoc = new DOMImplementation().createDocument(null, 'dest');
		var imported = noStackOverflow(function () {
			return destDoc.importNode(tree.root, true);
		});
		assert.strictEqual(imported.ownerDocument, destDoc);
		assert.strictEqual(imported.parentNode, null);
		assert.strictEqual(imported.toString(), DEEP_TREE_XML);
	},
	'normalize': function () {
		var tree = createDeepTree();
		noStackOverflow(function () {
			tree.root.normalize();
		});
		assert.strictEqual(tree.innermost.firstChild, tree.innermost.lastChild);
		assert.strictEqual(tree.innermost.firstChild.data, 'deep text');
	}
}).addBatch({
	// the advisory's proofs of concept: a deeply nested document parsed by DOMParser
	'parsed document: parseFromString, which normalizes the document when parsing ends': function () {
		var doc = noStackOverflow(function () {
			return parseXml(DEEP_TREE_XML);
		});
		assert.strictEqual(doc.documentElement.tagName, 'root');
		assert.strictEqual(doc.getElementsByTagName('n').length, DEEP_TREE_DEPTH);
	},
	'parsed document: serializeToString': function () {
		var doc = parseXml(DEEP_TREE_XML);
		var xml = noStackOverflow(function () {
			return new XMLSerializer().serializeToString(doc);
		});
		assert.strictEqual(xml, DEEP_TREE_XML);
	},
	'parsed document: normalize': function () {
		var doc = parseXml(DEEP_TREE_XML);
		noStackOverflow(function () {
			doc.documentElement.normalize();
		});
		assert.strictEqual(doc.documentElement.textContent, 'deep text');
	},
	'parsed document: getElementsByTagName, cloneNode(true) and importNode(node, true)': function () {
		var doc = parseXml(DEEP_TREE_XML);
		noStackOverflow(function () {
			assert.strictEqual(doc.getElementsByTagName('n').length, DEEP_TREE_DEPTH);
			assert.strictEqual(doc.documentElement.cloneNode(true).toString(), DEEP_TREE_XML);
			var destDoc = new DOMImplementation().createDocument(null, 'dest');
			assert.strictEqual(destDoc.importNode(doc.documentElement, true).toString(), DEEP_TREE_XML);
		});
	},
	// the children of a html script element are written by the serializer itself, a nested
	// script element must not bring the recursion back
	'parsed document: nested html script elements': function () {
		var source = '<x xmlns="' + HTML_NS + '"><script xmlns="">' + repeat('<script>', DEEP_TREE_DEPTH - 1) +
			'deep' + repeat('</script>', DEEP_TREE_DEPTH) + '</x>';
		var doc = parseXml(source);
		var xml = noStackOverflow(function () {
			return new XMLSerializer().serializeToString(doc);
		});
		assert.strictEqual(xml, source);
	}
}).addBatch({
	// the iterative traversals keep the order and the results of the recursive ones
	'getElementsByTagName lists the descendants in document order': function () {
		var doc = parseXml('<root><a><a1/><a2/></a><b><b1/></b></root>');
		assert.strictEqual(tagNames(doc.documentElement.getElementsByTagName('*')), 'a,a1,a2,b,b1');
		assert.strictEqual(tagNames(doc.getElementsByTagName('*')), 'root,a,a1,a2,b,b1');
	},
	'getElementById returns the first match in document order and stops there': function () {
		var doc = parseXml('<root><p><q id="x"/></p><r id="x"/></root>');
		assert.strictEqual(doc.getElementById('x').tagName, 'q');
		assert.strictEqual(doc.getElementById('missing'), null);
	},
	'textContent skips comments and processing instructions': function () {
		var doc = parseXml('<r>a<!--c-->b<?pi d?><x>c<y>d</y></x>e</r>');
		assert.strictEqual(doc.documentElement.textContent, 'abcde');
	},
	'normalize merges adjacent text nodes at every level': function () {
		var doc = new DOMImplementation().createDocument(null, 'root');
		var root = doc.documentElement;
		var x = doc.createElement('x');
		var y = doc.createElement('y');
		root.appendChild(doc.createTextNode('a'));
		root.appendChild(doc.createTextNode('b'));
		root.appendChild(x);
		root.appendChild(doc.createTextNode('g'));
		x.appendChild(doc.createTextNode('c'));
		x.appendChild(doc.createTextNode('d'));
		x.appendChild(y);
		y.appendChild(doc.createTextNode('e'));
		y.appendChild(doc.createTextNode('f'));
		root.normalize();
		assert.strictEqual(root.toString(), '<root>ab<x>cd<y>ef</y></x>g</root>');
		assert.strictEqual(root.firstChild.data, 'ab');
		assert.strictEqual(root.firstChild.nextSibling, x);
		assert.strictEqual(x.nextSibling.data, 'g');
		assert.strictEqual(x.nextSibling.nextSibling, null);
		assert.strictEqual(x.firstChild.data, 'cd');
		assert.strictEqual(x.firstChild.nextSibling, y);
		assert.strictEqual(y.firstChild, y.lastChild);
		assert.strictEqual(y.firstChild.data, 'ef');
	},
	'cloneNode copies the attributes and, when deep, the descendants': function () {
		var doc = parseXml('<root a="1"><x b="2">t<y/></x><!--c--></root>');
		var root = doc.documentElement;
		var deep = root.cloneNode(true);
		assert.strictEqual(deep.toString(), '<root a="1"><x b="2">t<y/></x><!--c--></root>');
		assert.notStrictEqual(deep.firstChild, root.firstChild);
		assert.strictEqual(deep.firstChild.parentNode, deep);
		assert.strictEqual(root.cloneNode(false).toString(), '<root a="1"/>');
	},
	'importNode copies the node and, when deep, the descendants into the document': function () {
		var src = parseXml('<root a="1"><x b="2">t<y/></x><!--c--></root>');
		var destDoc = new DOMImplementation().createDocument(null, 'dest');
		var deep = destDoc.importNode(src.documentElement, true);
		assert.strictEqual(deep.toString(), '<root a="1"><x b="2">t<y/></x><!--c--></root>');
		assert.strictEqual(deep.ownerDocument, destDoc);
		assert.strictEqual(deep.firstChild.ownerDocument, destDoc);
		assert.strictEqual(deep.firstChild.firstChild.ownerDocument, destDoc);
		assert.strictEqual(destDoc.importNode(src.documentElement, false).toString(), '<root a="1"/>');
	},
	'serializeToString applies nodeFilter to every node, including the children of a substituted node': function () {
		var doc = parseXml('<root><!--c--><a><old/></a><x/>t</root>');
		var replacement = doc.createElement('b');
		replacement.appendChild(doc.createElement('new'));
		var xml = new XMLSerializer().serializeToString(doc.documentElement, false, function (node) {
			switch (node.nodeName) {
			case '#comment':
				return null;
			case 'a':
				return replacement;
			case 'x':
				return 'X';
			case 'new':
				return 'N';
			}
			return node;
		});
		assert.strictEqual(xml, '<root><b>N</b>Xt</root>');
	},
	'serializeToString writes the children of a html script element with data as is': function () {
		var doc = new DOMImplementation().createDocument(HTML_NS, 'html');
		var script = doc.createElementNS(HTML_NS, 'script');
		script.appendChild(doc.createTextNode('if (a < b && c) {}'));
		doc.documentElement.appendChild(script);
		var xml = new XMLSerializer().serializeToString(doc);
		assert.notStrictEqual(xml.indexOf('<script>if (a < b && c) {}</script>'), -1, xml);
	}
}).run();
