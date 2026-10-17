import {defineConfig} from 'vite';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const stitch=fileURLToPath(new URL('../stitch_intentlock_operator_console/',import.meta.url));
const files:Record<string,[string,string]>={
 '/':['operator_live/code.html','text/html'],
 '/console.css':['operator_live/console.css','text/css'],
 '/support':['operator_live/support.html','text/html'],
 '/support/':['operator_live/support.html','text/html'],
 '/support.js':['operator_live/support.js','text/javascript'],
 '/metrics':['metrics_intentlock/code.html','text/html'],
 '/metrics/':['metrics_intentlock/code.html','text/html'],
 '/metrics/metrics.js':['metrics_intentlock/metrics.js','text/javascript'],
 '/metrics/metrics.css':['metrics_intentlock/metrics.css','text/css'],
};
export default defineConfig({resolve:{alias:{'react-dom':fileURLToPath(new URL('./node_modules/react-dom',import.meta.url)),react:fileURLToPath(new URL('./node_modules/react',import.meta.url))}},plugins:[{name:'stitch-live',configureServer(server){server.middlewares.use((request,response,next)=>{
 const file=files[(request.url??'').split('?')[0]];
 if(!file)return next();
 response.setHeader('Content-Type',file[1]);
 response.setHeader('Cache-Control','no-store');
 response.end(readFileSync(stitch+file[0]));
});}}],server:{fs:{allow:[fileURLToPath(new URL('..',import.meta.url))],deny:['**/.runtime/**','**/.env*','**/*.pem','**/*.key','**/*.textClipping','**/*.db','**/.git/**']},proxy:{'/v1':'http://127.0.0.1:8000','/public':'http://127.0.0.1:8000'}}});
