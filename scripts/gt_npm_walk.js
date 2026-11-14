// Ground-truth walker: list every installed npm package (identity = its package.json name@version).
// Walks <root>/node_modules recursively (incl. @scope dirs). Prints JSON lines {root,path,name,version}.
const fs = require('fs'), path = require('path');
const roots = process.argv.slice(2);
function pkg(dir) {
  try { const j = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'))); return j.name && j.version ? j : null; }
  catch { return null; }
}
function walk(nm, root) {
  let ents; try { ents = fs.readdirSync(nm, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (!e.isDirectory() || e.name.startsWith('.')) continue;
    const d = path.join(nm, e.name);
    if (e.name.startsWith('@')) { walk(d, root); continue; }
    const p = pkg(d);
    if (p) console.log(JSON.stringify({ root, path: d, name: p.name, version: p.version }));
    walk(path.join(d, 'node_modules'), root);
  }
}
for (const r of roots) {
  const self = pkg(r);
  if (self) console.log(JSON.stringify({ root: r, path: r, name: self.name, version: self.version, self: true }));
  walk(path.join(r, 'node_modules'), r);
}
