/*
 Simple Node.js test for the wasm-bindgen module's extractAndVerifySpell
 To run:
   node charms-lib/test/extractAndVerifySpell.node.test.js
*/

const assert = require('assert');
const path = require('path');
const fs = require('fs');

function main() {
    const wasmModulePath = path.resolve(__dirname, '../target/wasm-bindgen-nodejs/charms_lib.js');
    // Ensure wasm artifacts exist
    assert.ok(fs.existsSync(wasmModulePath), `Wasm JS glue not found at ${wasmModulePath}`);

    const wasm = require(wasmModulePath);
    assert.ok(typeof wasm.extractAndVerifySpell === 'function', 'extractAndVerifySpell export not found');

    const txJsonPath = path.resolve(__dirname, './bitcoin-tx.json');
    assert.ok(fs.existsSync(txJsonPath), `Sample tx JSON not found at ${txJsonPath}`);

    const tx = JSON.parse(fs.readFileSync(txJsonPath, 'utf8'));

    // Invoke the wasm function extractAndVerifySpell
    const res = wasm.extractAndVerifySpell(tx, true);
    console.log('[extractAndVerifySpell.test] OK');
    console.log('%o', res);
}

if (require.main === module) {
    try {
        main();
    } catch (err) {
        console.error('[extractAndVerifySpell.test] FAILED');
        console.error(err);
        process.exit(1);
    }
}
