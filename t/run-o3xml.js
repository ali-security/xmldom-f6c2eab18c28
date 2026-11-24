// Runs the test/3rd-cases suite: node-o3-xml's own DOM/XPath tests executed
// against xmldom through test/3rd-cases/o3xml.js + mock.js (mock.js replaces
// the native o3 module, so no native code is loaded).
//
// Upstream's node-o3-xml/test/test.js runs its tests in a loop that `break`s
// at the first failure and always exits 0. Here the loop is cut off when the
// file is loaded, and each test is run on its own and reported individually;
// the process exits non-zero if any non-excluded test fails.
var fs = require('fs');
var path = require('path');

// Tests whose expectations encode libxml2 (o3) behaviour that xmldom 0.1.31
// does not implement. Each is printed as SKIPPED with its reason.
var EXCLUDED = {
  test9: 'expects WRONG_DOCUMENT_ERR when appending an element created by another document; xmldom 0.1.31 adopts it silently',
  test30: 'expects WRONG_DOCUMENT_ERR when setting an attribute created by another document; xmldom 0.1.31 adopts it silently',
  test10: 'expects HIERARCHY_REQUEST_ERR when inserting an ancestor (the document element) into its own descendant; xmldom 0.1.31 performs no hierarchy check',
  test11: 'expects HIERARCHY_REQUEST_ERR when appending an ancestor (the document element) to its own descendant; xmldom 0.1.31 performs no hierarchy check',
  test29: 'expects setAttributeNode to MOVE an attribute owned by another element (libxml2 semantics); xmldom follows W3C DOM and throws INUSE_ATTRIBUTE_ERR',
  test32: 'Element.selectNodes (XPath) is an o3/libxml2 extension xmldom does not provide',
  test33: 'Element.selectNodes (XPath) is an o3/libxml2 extension xmldom does not provide',
  test34: 'Element.selectNodes (XPath) is an o3/libxml2 extension xmldom does not provide',
  test35: 'Element.selectNodes (XPath) is an o3/libxml2 extension xmldom does not provide',
  test36: 'Element.selectNodes (XPath) is an o3/libxml2 extension xmldom does not provide'
};

var testFile = require.resolve('node-o3-xml/test/test');
var origJs = require.extensions['.js'];
require.extensions['.js'] = function (module, filename) {
  if (filename !== testFile) {
    return origJs(module, filename);
  }
  var src = fs.readFileSync(filename, 'utf8');
  var idx = src.lastIndexOf('for (var i in test)');
  if (idx < 0) {
    throw new Error('node-o3-xml test loop not found in ' + filename);
  }
  module._compile(src.slice(0, idx) + '\nmodule.exports = test;\n', filename);
};

// Upstream entry point: installs the mock + compatibility shims, then loads
// node-o3-xml/test/test (through the hook above).
require(path.resolve(__dirname, '../test/3rd-cases'));
var tests = require.cache[testFile].exports;

var passed = 0, failed = 0, skipped = 0;
Object.keys(tests).forEach(function (name) {
  if (EXCLUDED[name]) {
    skipped++;
    console.log('SKIPPED o3xml ' + name + ': ' + EXCLUDED[name]);
    return;
  }
  var ok;
  try {
    ok = tests[name]();
  } catch (e) {
    console.log('o3xml ' + name + ' threw: ' + (e && e.stack || e));
    ok = false;
  }
  if (ok) {
    passed++;
    console.log('ok o3xml ' + name);
  } else {
    failed++;
    console.log('FAIL o3xml ' + name);
  }
});
console.log('SUITE-RESULT test/3rd-cases passed=' + passed + ' failed=' + failed +
  ' skipped=' + skipped + ' ' + (failed === 0 && passed > 0 ? 'PASS' : 'FAIL'));
if (failed !== 0 || passed === 0) {
  process.exit(1);
}
