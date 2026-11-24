// Runs ONE upstream vows suite file (test/**) and reports its result.
//
// Usage: node t/run-vows-suite.js <suite-file> [excluded vow name ...]
//
// The suite files call vows.describe(...).addBatch({...}).run() themselves, so
// they are required directly (the `vows` CLI finds nothing exported). This
// wrapper:
//   - deletes the vows named on the command line before the batch is
//     registered (each exclusion and its reason is listed in t/vows);
//   - switches the reporter to `spec` so every vow name and outcome is printed;
//   - prints a SUITE-RESULT line and exits non-zero unless every remaining vow
//     was honored.
var path = require('path');
var vows = require('vows');

var file = process.argv[2];
var excluded = process.argv.slice(3);
var suites = [];

function isPlainObject(o) {
  return o !== null && typeof o === 'object' &&
    Object.getPrototypeOf(o) === Object.prototype;
}

function prune(ctx) {
  Object.keys(ctx).forEach(function (k) {
    if (excluded.indexOf(k) !== -1) {
      console.log('SKIPPED vow "' + k + '" in ' + file + ' (reason printed at the top by t/vows)');
      delete ctx[k];
    } else if (isPlainObject(ctx[k])) {
      prune(ctx[k]);
    }
  });
}

var origDescribe = vows.describe;
vows.describe = function () {
  var suite = origDescribe.apply(vows, arguments);
  var origAddBatch = suite.addBatch;
  var origRun = suite.run;
  suite.addBatch = function (batch) {
    prune(batch);
    return origAddBatch.call(this, batch);
  };
  suite.run = function (options, callback) {
    options = options || {};
    if (!options.reporter) {
      options.reporter = 'spec';
    }
    suites.push(suite);
    return origRun.call(this, options, function (results) {
      suite.sealResults = results;
      if (callback) {
        callback(results);
      }
    });
  };
  return suite;
};

process.on('exit', function () {
  var h = 0, b = 0, e = 0, p = 0, t = 0;
  var ok = suites.length > 0;
  suites.forEach(function (s) {
    var r = s.sealResults;
    if (!r) {
      ok = false;
      return;
    }
    h += r.honored;
    b += r.broken;
    e += r.errored;
    p += r.pending;
    t += r.total;
  });
  if (t === 0 || h + p !== t) {
    ok = false;
  }
  console.log('SUITE-RESULT ' + file + ' honored=' + h + ' broken=' + b +
    ' errored=' + e + ' pending=' + p + ' total=' + t + ' ' + (ok ? 'PASS' : 'FAIL'));
  if (!ok) {
    process.exit(1);
  }
});

require(path.resolve(file));
