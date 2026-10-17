import { defineConfig } from 'vite';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const stitch=fileURLToPath(new URL('../stitch_intentlock_operator_console/metrics_intentlock/',import.meta.url));
export default defineConfig({plugins:[{name:'stitch-metrics',configureServer(server){server.middlewares.use((request,response,next)=>{const path=(request.url??'').split('?')[0];const files:Record<string,[string,string]>={'/metrics':['code.html','text/html'],'/metrics/':['code.html','text/html'],'/metrics/metrics.js':['metrics.js','text/javascript'],'/metrics/metrics.css':['metrics.css','text/css']};const file=files[path];if(!file)return next();response.setHeader('Content-Type',file[1]);response.end(readFileSync(stitch+file[0]));});}}],server:{proxy:{'/v1':'http://127.0.0.1:8000','/public':'http://127.0.0.1:8000'}}});
