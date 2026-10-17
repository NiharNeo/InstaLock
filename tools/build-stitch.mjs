/** Build only live, database-backed Stitch interfaces; reference screens stay out of runtime. */
import {copyFileSync,mkdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const source=fileURLToPath(new URL('../stitch_intentlock_operator_console/',import.meta.url));
if(process.argv.includes('--prepare')){const publicDir=fileURLToPath(new URL('../web/public/',import.meta.url));mkdirSync(publicDir,{recursive:true});copyFileSync(source+'operator_live/console.css',publicDir+'console.css');copyFileSync(source+'operator_live/code.html',fileURLToPath(new URL('../web/index.html',import.meta.url)));process.exit(0);}
const target=fileURLToPath(new URL('../web/dist/',import.meta.url));
for(const [from,to] of [['operator_live/support.html','support/index.html'],['operator_live/console.css','console.css'],['operator_live/support.js','support.js'],['metrics_intentlock/code.html','metrics/index.html'],['metrics_intentlock/metrics.css','metrics/metrics.css'],['metrics_intentlock/metrics.js','metrics/metrics.js']]){
 mkdirSync(new URL('.',new URL(to,'file://'+target)),{recursive:true});
 copyFileSync(source+from,target+to);
}
