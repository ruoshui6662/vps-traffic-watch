/* ============================================================
   vpsmon 前端一致性校验
   - 提取 index.html 中所有 id，检查重复
   - 提取 app.js 中所有 getElementById / $('...') / querySelector('...') 引用
   - 校验：JS 引用的 id 必须存在于 HTML；querySelector 的选择器
     （.class / #id）必须存在于 HTML
   用法：node scripts/check_frontend_ids.js
   退出码：0 = 一致；1 = 存在问题
   ============================================================ */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const HTML = path.join(ROOT, 'vpsmon', 'static', 'index.html');
const JS = path.join(ROOT, 'vpsmon', 'static', 'js', 'app.js');

const html = fs.readFileSync(HTML, 'utf8');
const js = fs.readFileSync(JS, 'utf8');

/* ---------- 1. HTML 中的 id ---------- */
const htmlIds = new Set();
const idDuplicates = [];
{
  const re = /\bid="([^"]+)"/g;
  let m;
  while ((m = re.exec(html))) {
    if (htmlIds.has(m[1])) idDuplicates.push(m[1]);
    htmlIds.add(m[1]);
  }
}

/* ---------- 2. app.js 中的引用 ---------- */
function collectRefs(re, src) {
  const set = new Set();
  let m;
  while ((m = re.exec(src))) set.add(m[1]);
  return set;
}
const jsGetById = collectRefs(/\bgetElementById\s*\(\s*['"]([^'"]+)['"]\s*\)/g, js);
const jsDollar = collectRefs(/\$\s*\(\s*['"]([^'"]+)['"]\s*\)/g, js);
const jsQuery = collectRefs(/\bquerySelector\s*\(\s*['"]([^'"]+)['"]\s*\)/g, js);

const jsIds = new Set([...jsGetById, ...jsDollar]);

/* ---------- 3. 校验 ---------- */
const problems = [];
if (idDuplicates.length) {
  problems.push('HTML 存在重复 id: ' + [...new Set(idDuplicates)].join(', '));
}
for (const id of [...jsIds].sort()) {
  if (!htmlIds.has(id)) problems.push('app.js 引用了不存在的 id: ' + id);
}
for (const sel of [...jsQuery].sort()) {
  if (sel.startsWith('#')) {
    const id = sel.slice(1);
    if (!htmlIds.has(id)) problems.push('querySelector 引用了不存在的 id: ' + sel);
  } else if (sel.startsWith('.')) {
    const cls = sel.slice(1);
    const re = new RegExp('class="[^"]*\\b' + cls.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
    if (!re.test(html)) problems.push('querySelector 引用了不存在的 class: ' + sel);
  } else {
    problems.push('querySelector 使用了非 .class/#id 选择器: ' + sel);
  }
}

/* ---------- 4. 报告 ---------- */
console.log('HTML ids : ' + htmlIds.size + ' 个');
console.log('JS 引用的 id: getElementById=' + jsGetById.size +
  ' $()=' + jsDollar.size + '（去重后 ' + jsIds.size + ' 个）');
console.log('JS querySelector 选择器: ' + jsQuery.size + ' 个');
console.log('未在 HTML 出现的 id 列表（JS 未引用 / 纯样式钩子，允许）:');
const unreferenced = [...htmlIds].filter((id) => !jsIds.has(id)).sort();
console.log('  ' + (unreferenced.length ? unreferenced.join(', ') : '(无)'));

if (problems.length) {
  console.error('\n[FAIL] 发现 ' + problems.length + ' 个问题:');
  problems.forEach((p) => console.error('  - ' + p));
  process.exit(1);
}
console.log('\n[PASS] HTML id / app.js 引用集合一致 ✔');
