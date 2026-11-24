var wows = require('vows');
var assert = require('assert');
var DOMParser = require('xmldom').DOMParser;
var XMLSerializer = require('xmldom').XMLSerializer;
var DOMImplementation = require('xmldom/dom').DOMImplementation;

// CVE-2026-34601: CDATASection data containing "]]>" was serialized verbatim,
// which terminates the CDATA section early so the rest of the data became
// live markup in the serialized XML.
// https://github.com/xmldom/xmldom/security/advisories/GHSA-wh4c-j3r5-mjhp

// the code is a literal so the vows report the missing check (and not a
// TypeError) when DOMException is not exported
var INVALID_STATE_ERR = 11;

// GHSA-j759-j44w-7fr8 proof of concept: closes the comment and injects an element
var COMMENT_PAYLOAD = '--><injected attr="1"/><!--';

function createRootDocument() {
  return new DOMImplementation().createDocument(null, 'root', null);
}

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

// Serializes, then re-parses, and returns true if an <injected> element appears in the tree.
function isInjected(root) {
  var xml = new XMLSerializer().serializeToString(root);
  var reparsed = new DOMParser().parseFromString(xml, 'text/xml');
  return reparsed.getElementsByTagName('injected').length > 0;
}

wows.describe('XML Serializer').addBatch({
  'text node containing "]]>"': function() {
    var doc = new DOMParser().parseFromString('<test/>', 'text/xml');
    doc.documentElement.appendChild(doc.createTextNode('hello ]]> there'));
    console.assert(doc.documentElement.firstChild.toString() == 'hello ]]> there',doc.documentElement.firstChild.toString());
  },
  '<script> element with no children': function() {
    var doc = new DOMParser({xmlns:{xmlns:'http://www.w3.org/1999/xhtml'}}).parseFromString('<html2><script></script></html2>', 'text/html');
    //console.log(doc.documentElement.firstChild.toString(true))
    console.assert(doc.documentElement.firstChild.toString() == '<script></script>');
  },
}).addBatch({
  // CVE-2026-34601: XMLSerializer CDATASection serialization
  'serializes a safe CDATASection unchanged': function () {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createCDATASection('safe data'));
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[safe data]]></root>');
  },
  'splits a CDATASection whose data contains "]]>"': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'splits multiple "]]>" occurrences': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'a]]>b]]>c';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[a]]]]><![CDATA[>b]]]]><![CDATA[>c]]></root>');
  },
  'split output round-trips through DOMParser to equivalent content': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    var serialized = new XMLSerializer().serializeToString(doc.documentElement);
    var reparsed = new DOMParser().parseFromString(serialized, 'text/xml');
    assert.equal(reparsed.documentElement.textContent, 'foo]]>bar');
  },
  'mutation vectors': {
    'appendData introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.appendData(']]><injected/>');
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    'insertData introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.insertData(2, ']]><injected/>');
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    'replaceData introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe data');
      doc.documentElement.appendChild(cdata);
      cdata.replaceData(4, 5, ']]><injected/>');
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    '.data assignment introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.data = 'evil]]><injected/>';
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    '.textContent assignment introduces "]]>" safely': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.textContent = 'evil]]><injected/>';
      assert.strictEqual(isInjected(doc.documentElement), false);
    },
    'Node.toString and NodeList.toString split "]]>" too': function () {
      var doc = createRootDocument();
      var cdata = doc.createCDATASection('safe');
      doc.documentElement.appendChild(cdata);
      cdata.data = 'evil]]><injected/>';
      var expected = '<root><![CDATA[evil]]]]><![CDATA[><injected/>]]></root>';
      assert.equal(doc.toString(), expected);
      assert.equal(doc.documentElement.toString(), expected);
      assert.equal(doc.childNodes.toString(), expected);
    }
  }
}).addBatch({
  // CVE-2026-34601: XMLSerializer serializeToString requireWellFormed option
  'CDATA with "]]>" still splits when no options are passed (regression)': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'CDATA with "]]>" still splits when options is null (regression)': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc.documentElement, false, null, null),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'CDATA with "]]>" still splits when requireWellFormed is false': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assert.equal(new XMLSerializer().serializeToString(doc, false, null, {requireWellFormed: false}),
      '<root><![CDATA[foo]]]]><![CDATA[>bar]]></root>');
  },
  'requireWellFormed: true on a safe CDATA does not throw': function () {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createCDATASection('safe data'));
    assert.equal(new XMLSerializer().serializeToString(doc, false, null, {requireWellFormed: true}),
      '<root><![CDATA[safe data]]></root>');
  },
  'requireWellFormed: true on CDATA with "]]>" throws': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assertThrowsDOMException(INVALID_STATE_ERR, function () {
      new XMLSerializer().serializeToString(doc, false, null, {requireWellFormed: true});
    });
  },
  'node.toString with requireWellFormed: true on CDATA with "]]>" throws': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assertThrowsDOMException(INVALID_STATE_ERR, function () {
      doc.toString(false, null, {requireWellFormed: true});
    });
  },
  'nodeList.toString with requireWellFormed: true on CDATA with "]]>" throws': function () {
    var doc = createRootDocument();
    var cdata = doc.createCDATASection('safe');
    cdata.data = 'foo]]>bar';
    doc.documentElement.appendChild(cdata);
    assertThrowsDOMException(INVALID_STATE_ERR, function () {
      doc.childNodes.toString(false, null, {requireWellFormed: true});
    });
  }
}).addBatch({
  // CVE-2026-41672: Comment data was serialized as is, so "-->" in the data closed the
  // comment early and the rest of the data became live markup.
  // https://github.com/xmldom/xmldom/security/advisories/GHSA-j759-j44w-7fr8
  'default: comment with "-->" in data emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-->world'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><!--hello-->world--></root>');
  },
  'default: comment with "--" in data emits verbatim - no throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello--world'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><!--hello--world--></root>');
  },
  'requireWellFormed: true on comment with invalid XML Char (\\x00) throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello' + String.fromCharCode(0) + 'world'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment with "-->" throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-->world'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment with "--" (no "-->") throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello--world'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment whose data ends with "-" throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-'));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  },
  'requireWellFormed: true on comment with clean data does not throw': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('clean comment'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><!--clean comment--></root>');
  },
  'mutation vector: appendData("-->") then requireWellFormed: true throws InvalidStateError': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('clean');
    doc.documentElement.appendChild(comment);
    comment.appendData('-->');
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
    });
  }
}).addBatch({
  // the advisory's proof of concept, and every way it lists to get the payload into a comment
  'advisory PoC: injected element survives a default round-trip': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assert.strictEqual(new XMLSerializer().serializeToString(doc), '<root><!----><injected attr="1"/><!----></root>');
    assert.strictEqual(isInjected(doc.documentElement), true);
  },
  'advisory PoC: createComment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertCommentRejected(doc);
  },
  'insertData payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe');
    doc.documentElement.appendChild(comment);
    comment.insertData(2, COMMENT_PAYLOAD);
    assertCommentRejected(doc);
  },
  'replaceData payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe data');
    doc.documentElement.appendChild(comment);
    comment.replaceData(4, 5, COMMENT_PAYLOAD);
    assertCommentRejected(doc);
  },
  '.data assignment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe');
    doc.documentElement.appendChild(comment);
    comment.data = COMMENT_PAYLOAD;
    assertCommentRejected(doc);
  },
  '.textContent assignment payload throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var comment = doc.createComment('safe');
    doc.documentElement.appendChild(comment);
    comment.textContent = COMMENT_PAYLOAD;
    assertCommentRejected(doc);
  },
  'payload in a parsed document comment throws with requireWellFormed: true': function() {
    var doc = new DOMParser().parseFromString('<root><!-- safe --></root>', 'text/xml');
    doc.documentElement.firstChild.data = COMMENT_PAYLOAD;
    assertCommentRejected(doc);
  },
  'payload in a nested comment throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var child = doc.createElement('child');
    doc.documentElement.appendChild(child);
    child.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertCommentRejected(doc);
  },
  'payload in a DocumentFragment comment throws with requireWellFormed: true': function() {
    var doc = createRootDocument();
    var fragment = doc.createDocumentFragment();
    fragment.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      new XMLSerializer().serializeToString(fragment, false, null, { requireWellFormed: true });
    });
  },
  'node.toString with requireWellFormed: true on a comment payload throws': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.toString(false, null, { requireWellFormed: true });
    });
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.firstChild.toString(false, null, { requireWellFormed: true });
    });
  },
  'NodeList.toString with requireWellFormed: true on a comment payload throws': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment(COMMENT_PAYLOAD));
    assertThrowsDOMException(INVALID_STATE_ERR, function() {
      doc.documentElement.childNodes.toString(false, null, { requireWellFormed: true });
    });
  }
}).addBatch({
  'requireWellFormed: true on comment with an unpaired surrogate throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('a' + String.fromCharCode(0xD800) + 'b'));
    assertCommentRejected(doc);
    doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('a' + String.fromCharCode(0xDC00)));
    assertCommentRejected(doc);
  },
  'requireWellFormed: true on comment with U+FFFE throws InvalidStateError': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('a' + String.fromCharCode(0xFFFE)));
    assertCommentRejected(doc);
  },
  'requireWellFormed: true on comment with a surrogate pair (U+1F600) does not throw': function() {
    var doc = createRootDocument();
    var data = 'smile ' + String.fromCharCode(0xD83D, 0xDE00) + ' tab\tnewline\n';
    doc.documentElement.appendChild(doc.createComment(data));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }),
      '<root><!--' + data + '--></root>');
  },
  'requireWellFormed: true on a parsed well-formed comment round-trips': function() {
    var xml = '<root><!-- a - b --><child/></root>';
    var doc = new DOMParser().parseFromString(xml, 'text/xml');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true }), xml);
  },
  'requireWellFormed: false keeps the verbatim comment output': function() {
    var doc = createRootDocument();
    doc.documentElement.appendChild(doc.createComment('hello-->world'));
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: false }),
      '<root><!--hello-->world--></root>');
    assert.strictEqual(new XMLSerializer().serializeToString(doc, false, null, null),
      '<root><!--hello-->world--></root>');
  }
}).run();

// Serializing `doc` with requireWellFormed throws, so the payload never reaches the output.
function assertCommentRejected(doc) {
  assertThrowsDOMException(INVALID_STATE_ERR, function() {
    new XMLSerializer().serializeToString(doc, false, null, { requireWellFormed: true });
  });
}
