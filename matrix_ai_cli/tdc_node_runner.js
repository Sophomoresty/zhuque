const fs=require('fs');
const path=require('path');
const code=fs.readFileSync(process.argv[2]||'/tmp/matrix-captcha/current_tdc.js','utf8');
const cfg=process.env.TDC_ENV_CFG ? JSON.parse(process.env.TDC_ENV_CFG) : {};
const waitMs=Number(cfg.waitMs || process.env.TDC_WAIT_MS || 0);

async function runJsdom(){
  let JSDOM;
  try { ({JSDOM}=require('jsdom')); } catch(e) { return {ok:false, missingJsdom:true, error:String(e&&e.message||e)}; }
  const dom=new JSDOM('<!doctype html><html><head></head><body><div id="app"><button id="tcaptcha_drag_button"></button></div></body></html>',{
    url: cfg.url || 'https://captcha.gtimg.com/static/template/drag_ele.86303081.html',
    referrer: cfg.referrer || 'https://matrix.tencent.com/',
    pretendToBeVisual:true, runScripts:'outside-only', resources:'usable', storageQuota:10000000,
  });
  const w=dom.window;
  function def(obj,name,val){try{Object.defineProperty(obj,name,{value:val,configurable:true,writable:true});}catch(e){try{obj[name]=val;}catch(_){}}}
  function nav(name,val){def(w.navigator,name,val)}
  nav('userAgent', cfg.ua || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36');
  nav('platform', cfg.platform || 'Win32'); nav('vendor', cfg.vendor || 'Google Inc.'); nav('language', cfg.language || 'zh-CN'); nav('languages', cfg.languages || ['zh-CN','zh']); nav('webdriver', false); nav('hardwareConcurrency', cfg.hardwareConcurrency || 16); nav('deviceMemory', cfg.deviceMemory || 8); nav('maxTouchPoints', cfg.maxTouchPoints || 0); nav('cookieEnabled', true); nav('pdfViewerEnabled', true);
  nav('plugins', cfg.plugins === 'empty' ? [] : [{name:'PDF Viewer',filename:'internal-pdf-viewer',description:'Portable Document Format'},{name:'Chrome PDF Viewer'},{name:'Chromium PDF Viewer'},{name:'Microsoft Edge PDF Viewer'},{name:'WebKit built-in PDF'}]);
  nav('mimeTypes', cfg.plugins === 'empty' ? [] : [{type:'application/pdf',suffixes:'pdf',description:'Portable Document Format'}]);
  for (const [k,v] of Object.entries(cfg.screen || {width:1920,height:1080,availWidth:1920,availHeight:1032,colorDepth:24,pixelDepth:24})) def(w.screen,k,v);
  def(w,'innerWidth',cfg.innerWidth||1920); def(w,'innerHeight',cfg.innerHeight||945); def(w,'outerWidth',cfg.outerWidth||1936); def(w,'outerHeight',cfg.outerHeight||1048); def(w,'devicePixelRatio',cfg.devicePixelRatio||1);
  try { def(w.document,'referrer',cfg.referrer || 'https://matrix.tencent.com/'); } catch(e){}
  try { def(w,'pageXOffset',0); def(w,'pageYOffset',0); } catch(e){}
  w.chrome={runtime:{}, app:{}, csi(){}, loadTimes(){return {}}};
  w.matchMedia=(q)=>({matches: /color-gamut:\s*srgb|dynamic-range:\s*standard|prefers-contrast:\s*no-preference|prefers-reduced-motion:\s*no-preference|prefers-reduced-transparency:\s*no-preference|inverted-colors:\s*none|forced-colors:\s*none|min-monochrome:\s*0|max-monochrome:\s*0/.test(q), media:q, onchange:null, addListener(){}, removeListener(){}, addEventListener(){}, removeEventListener(){}, dispatchEvent(){return false;}});
  if(w.HTMLCanvasElement){
    w.HTMLCanvasElement.prototype.toDataURL=function(){return cfg.canvasData || 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJYAAABkCAYAAABmWfKfAAAACXBIWXMAAAsTAAALEwEAmpwYAAA='};
    w.HTMLCanvasElement.prototype.getContext=function(type){
      if(String(type).includes('webgl')) {
        if(cfg.webgl===false) return null;
        return {VERSION:0x1F02,VENDOR:0x1F00,RENDERER:0x1F01,SHADING_LANGUAGE_VERSION:0x8B8C,FRAGMENT_SHADER:0x8B30,VERTEX_SHADER:0x8B31,LOW_FLOAT:0x8DF0,MEDIUM_FLOAT:0x8DF1,HIGH_FLOAT:0x8DF2,LOW_INT:0x8DF3,MEDIUM_INT:0x8DF4,HIGH_INT:0x8DF5,getParameter(p){const m={0x1F02:'WebGL 1.0 (OpenGL ES 2.0 Chromium)',0x1F00:'WebKit',0x1F01:'WebKit WebGL',0x8B8C:'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)',37445:'Google Inc. (NVIDIA)',37446:'ANGLE (NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0)'}; return m[p]||0;},getSupportedExtensions(){return ['ANGLE_instanced_arrays','EXT_blend_minmax','EXT_color_buffer_half_float','EXT_texture_filter_anisotropic','OES_element_index_uint','OES_standard_derivatives','OES_texture_float','OES_vertex_array_object','WEBGL_debug_renderer_info','WEBGL_lose_context'];},getExtension(name){ if(name==='WEBGL_debug_renderer_info') return {UNMASKED_VENDOR_WEBGL:37445,UNMASKED_RENDERER_WEBGL:37446}; return {};},getContextAttributes(){return {alpha:true,antialias:true,depth:true,desynchronized:false,failIfMajorPerformanceCaveat:false,powerPreference:'default',premultipliedAlpha:true,preserveDrawingBuffer:false,stencil:false,willReadFrequently:false};},getShaderPrecisionFormat(){return {rangeMin:127,rangeMax:127,precision:23};},canvas:this,addEventListener(){},removeEventListener(){}};
      }
      return {fillRect(){},clearRect(){},getImageData(){return {data:new Uint8ClampedArray(400)}},putImageData(){},createImageData(){return []},setTransform(){},drawImage(){},save(){},fillText(){},restore(){},beginPath(){},moveTo(){},lineTo(){},closePath(){},stroke(){},translate(){},scale(){},rotate(){},arc(){},fill(){},measureText(){return {width:12}},transform(){},rect(){},clip(){},canvas:this};
    };
  }
  w.AudioContext=function(){this.baseLatency=0.01; this.createOscillator=()=>({connect(){},start(){},stop(){},frequency:{value:0},type:''}); this.createAnalyser=()=>({connect(){},fftSize:0,frequencyBinCount:32,getFloatFrequencyData(a){for(let i=0;i<a.length;i++)a[i]=-100;}}); this.createGain=()=>({connect(){},gain:{value:0}}); this.createDynamicsCompressor=()=>({connect(){},threshold:{value:0},knee:{value:0},ratio:{value:0},attack:{value:0},release:{value:0}}); this.destination={}; this.close=()=>Promise.resolve();};
  w.OfflineAudioContext=function(){this.createOscillator=()=>({connect(){},start(){},frequency:{value:0},type:''}); this.createDynamicsCompressor=()=>({connect(){},threshold:{value:0},knee:{value:0},ratio:{value:0},attack:{value:0},release:{value:0}}); this.destination={}; this.startRendering=()=>Promise.resolve({getChannelData(){return new Float32Array(5000).fill(0.1)}});};
  w.performance.getEntriesByType=(type)=> type==='resource' ? [{initiatorType:'script',name:'https://captcha.gtimg.com/TCaptcha.js',duration:23},{initiatorType:'script',name:'https://captcha.gtimg.com/static/tcaptcha-frame.9ef230b0.js',duration:9},{initiatorType:'script',name:'https://t.captcha.qq.com/cap_union_prehandle',duration:126},{initiatorType:'iframe',name:'https://captcha.gtimg.com/static/template/drag_ele.86303081.html',duration:20},{initiatorType:'script',name:'https://captcha.gtimg.com/static/dy-jy.js',duration:0},{initiatorType:'script',name:'https://captcha.gtimg.com/static/dy-ele.fcc7d773.js',duration:0},{initiatorType:'script',name:'https://t.captcha.qq.com/tdc.js',duration:247},{initiatorType:'xmlhttprequest',name:'https://t.captcha.qq.com/cap_union_new_verify',duration:187}] : [];
  function fire(kind, target=w.document) { try { const x=Number(cfg.eventX||960), y=Number(cfg.eventY||470); const ev=new w.MouseEvent(kind,{bubbles:true,cancelable:true,view:w,screenX:x+8,screenY:y+85,clientX:x,clientY:y,button:0,buttons:(kind==='mouseup'||kind==='pointerup')?0:1,movementX:1,movementY:0}); target.dispatchEvent(ev); if(w.document.body) w.document.body.dispatchEvent(ev); } catch(e){} }
  const started=Date.now();
  w.eval(code);
  if(w.document && w.document.body){ try { w.document.body.innerHTML='<div id=\"tcaptcha_transform\" style=\"width:300px;height:230px;\"><div id=\"slideBg\"></div><div id=\"tcaptcha_drag_button\"></div><button id=\"tcaptcha_submit\"></button></div>'; } catch(e){} }
  const preSeq=cfg.preSeq||[]; for (const x of preSeq) { try { w.TDC.setData(x); } catch(e){} }
  try { ['mouseover','mouseenter','mousemove','pointerover','pointerenter','pointermove','mousedown','pointerdown'].forEach(k=>fire(k)); } catch(e){}
  const int=setInterval(()=>{fire('mousemove'); fire('pointermove'); fire('mouseover');}, Math.max(30, Number(cfg.eventEvery||120)));
  await new Promise(r=>setTimeout(r, waitMs));
  try { ['mousemove','pointermove','mouseover','mouseup','pointerup','click'].forEach(k=>fire(k)); } catch(e){}
  clearInterval(int);
  const seq=cfg.seq||[]; for (const x of seq) { try { w.TDC.setData(x); } catch(e) { console.error('setDataErr', e.stack||String(e)); } }
  const info=w.TDC.getInfo(); const data=w.TDC.getData(true);
  console.error('eval ok jsdom', Date.now()-started, !!w.TDC, w.TDC_NAME, String(w[w.TDC_NAME]||'').length, Object.keys(w.TDC), 'dataLen', String(data||'').length);
  return {info,data,data_len:String(data||'').length,decoded_len:decodeURIComponent(String(data||'')).length,prefix:String(data||'').slice(0,200),runtime:'jsdom',cfg:{...cfg,waitMs}};
}

function makeAny(name='any'){
  const fn=function(){return proxy};
  const proxy=new Proxy(fn,{
    get(target,prop){
      if(prop===Symbol.toPrimitive) return ()=>'';
      if(prop==='toString') return ()=>'[object Object]';
      if(prop==='valueOf') return ()=>0;
      if(prop==='length') return 1;
      if(prop==='then') return undefined;
      if(prop==='call') return (thisArg,...args)=>proxy;
      if(prop==='apply') return (thisArg,args)=>proxy;
      if(prop==='bind') return (...args)=>proxy;
      if(prop==='addEventListener'||prop==='removeEventListener'||prop==='attachEvent'||prop==='detachEvent') return ()=>{};
      if(prop==='getContext') return ()=>makeAny(name+'.ctx');
      if(prop==='getBoundingClientRect') return ()=>({left:0,top:0,width:0,height:0,right:0,bottom:0});
      if(prop==='appendChild'||prop==='removeChild'||prop==='setAttribute'||prop==='getAttribute') return ()=>proxy;
      if(prop==='style') return makeAny(name+'.style');
      if(prop==='documentElement'||prop==='body'||prop==='parentNode'||prop==='contentWindow') return makeAny(name+'.'+String(prop));
      return makeAny(name+'.'+String(prop));
    },
    apply(target,thisArg,args){ return proxy; }, construct(target,args){ return proxy; }, has(){return true;}, ownKeys(){return [];}, getOwnPropertyDescriptor(){return {configurable:true, enumerable:false, writable:true, value:proxy};}
  });
  return proxy;
}
function runFallback(){
  const any=makeAny();
  global.window=global; global.self=global; global.parent=global; global.top=global;
  global.atob=(s)=>Buffer.from(s,'base64').toString('binary'); global.btoa=(s)=>Buffer.from(s,'binary').toString('base64');
  global.addEventListener=()=>{}; global.removeEventListener=()=>{}; global.attachEvent=()=>{}; global.detachEvent=()=>{};
  global.navigator={userAgent:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36', platform:'Win32', language:'zh-CN', languages:['zh-CN','zh'], cookieEnabled:true, webdriver:false, hardwareConcurrency:16, deviceMemory:8, plugins:[1,2,3], mimeTypes:[1,2], maxTouchPoints:0};
  global.screen={width:1920,height:1080,availWidth:1920,availHeight:1040,colorDepth:24,pixelDepth:24};
  global.location={href:'https://captcha.gtimg.com/static/template/drag_ele.86303081.html', protocol:'https:', host:'captcha.gtimg.com', hostname:'captcha.gtimg.com', pathname:'/static/template/drag_ele.86303081.html'};
  global.history={length:1};
  global.document={addEventListener:()=>{}, removeEventListener:()=>{}, attachEvent:()=>{}, detachEvent:()=>{}, documentElement:any, body:any, defaultView:global, createElement:(tag)=>makeAny('el.'+tag), createEvent:()=>makeAny('event'), getElementsByTagName:()=>[], querySelectorAll:()=>[], querySelector:()=>null, cookie:'', referrer:'https://matrix.tencent.com/', title:'', characterSet:'UTF-8', compatMode:'CSS1Compat'};
  global.localStorage={getItem:()=>null,setItem:()=>{},removeItem:()=>{},key:()=>null,length:0}; global.sessionStorage=global.localStorage;
  global.MutationObserver=function(){this.observe=()=>{}; this.disconnect=()=>{}}; global.XMLHttpRequest=function(){}; global.fetch=()=>Promise.resolve(any);
  global.performance={now:()=>Date.now(), timing:{navigationStart:Date.now()-1000}, getEntriesByType:()=>[]};
  const start=Date.now(); eval(code);
  const seq=cfg.seq||[]; if(global.TDC) for (const x of seq) { try { global.TDC.setData(x); } catch(e){} }
  const info=global.TDC&&global.TDC.getInfo&&global.TDC.getInfo(); const data=global.TDC&&global.TDC.getData&&global.TDC.getData(true);
  console.error('eval ok fallback', Date.now()-start, !!global.TDC, global.TDC_NAME, String(global[global.TDC_NAME]||'').length, global.TDC&&Object.keys(global.TDC));
  return {info,data,data_len:String(data||'').length,prefix:String(data||'').slice(0,500),runtime:'fallback'};
}
(async()=>{
  let out=await runJsdom();
  if(!out || out.missingJsdom) out=runFallback();
  console.log(JSON.stringify(out));
})().catch(e=>{console.log(JSON.stringify({err:String(e&&e.stack||e)})); process.exit(1);});
