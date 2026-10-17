/** Build the user-selected Stitch Metrics source without copying sample business screens. */
import {copyFileSync,mkdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const source=fileURLToPath(new URL('../stitch_intentlock_operator_console/metrics_intentlock/',import.meta.url));
const target=fileURLToPath(new URL('../web/dist/metrics/',import.meta.url));
mkdirSync(target,{recursive:true});
for(const [from,to] of [['code.html','index.html'],['metrics.css','metrics.css'],['metrics.js','metrics.js']])copyFileSync(source+from,target+to);
