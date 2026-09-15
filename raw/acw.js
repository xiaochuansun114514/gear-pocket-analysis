const fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
let cookie=null;
const document={ get cookie(){return cookie;}, set cookie(v){cookie=v;},
  location:{reload(){},href:''}, getElementsByTagName(){return [];},
  createElement(){return {};}, cookie2:'' };
document.location.reload=()=>{};
global.document=document;
global.window={document,location:document.location,navigator:{userAgent:'Mozilla/5.0'}};
global.navigator={userAgent:'Mozilla/5.0'};
try{ eval(src); }catch(e){ console.error('EVAL_ERR',e.message); }
console.log(cookie||'NOCOOKIE');
