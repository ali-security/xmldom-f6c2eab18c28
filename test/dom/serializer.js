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
}).run();
