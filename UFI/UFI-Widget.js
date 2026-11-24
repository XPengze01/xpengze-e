// U30 Air Widget 1.4 — Egern medium, fixed white, read-only.
const bytes = s => Array.from(encodeURIComponent(s).replace(/%([0-9A-F]{2})/g,(_,x)=>String.fromCharCode(parseInt(x,16))),c=>c.charCodeAt(0));
const hex = a => a.map(x=>x.toString(16).padStart(2,'0')).join('');
const rol=(x,n)=>(x<<n)|(x>>>(32-n));
const ror=(x,n)=>(x>>>n)|(x<<(32-n));
function padded(a,little){const b=a.slice(), n=a.length*8;b.push(128);while(b.length%64!==56)b.push(0);for(let i=0;i<8;i++){const j=little?i:7-i;b.push(Math.floor(n/Math.pow(256,j))%256)}return b}
function word(a,i,little){return little?(a[i]|a[i+1]<<8|a[i+2]<<16|a[i+3]<<24):(a[i]<<24|a[i+1]<<16|a[i+2]<<8|a[i+3])}
function output(h,little){return h.flatMap(x=>[0,1,2,3].map(i=>(x>>>((little?i:3-i)*8))&255))}
const primes=[];for(let i=2;primes.length<64;i++){if(primes.every(p=>p*p>i||i%p!==0))primes.push(i)}
const frac=x=>((x-Math.floor(x))*4294967296)|0;
const sk=primes.map(p=>frac(Math.cbrt(p)));
function sha256(a){const b=padded(a,false),h=primes.slice(0,8).map(p=>frac(Math.sqrt(p)));for(let j=0;j<b.length;j+=64){const w=[];for(let i=0;i<16;i++)w.push(word(b,j+4*i,false));for(let i=16;i<64;i++){let x=w[i-15],y=w[i-2];w.push((w[i-16]+(ror(x,7)^ror(x,18)^(x>>>3))+w[i-7]+(ror(y,17)^ror(y,19)^(y>>>10)))|0)}let [a,c,d,e,f,g,k,l]=h;for(let i=0;i<64;i++){let t1=(l+(ror(f,6)^ror(f,11)^ror(f,25))+((f&g)^(~f&k))+sk[i]+w[i])|0,t2=((ror(a,2)^ror(a,13)^ror(a,22))+((a&c)^(a&d)^(c&d)))|0;[a,c,d,e,f,g,k,l]=[(t1+t2)|0,a,c,d,(e+t1)|0,f,g,k]}[a,c,d,e,f,g,k,l].forEach((x,i)=>h[i]=(h[i]+x)|0)}return output(h,false)}
const mk=Array.from({length:64},(_,i)=>Math.floor(Math.abs(Math.sin(i+1))*4294967296)|0);
function md5(a){const b=padded(a,true),h=[0x67452301,0xefcdab89,0x98badcfe,0x10325476];const s=[[7,12,17,22],[5,9,14,20],[4,11,16,23],[6,10,15,21]];for(let j=0;j<b.length;j+=64){const m=Array.from({length:16},(_,i)=>word(b,j+4*i,true));let [a,c,d,e]=h;for(let i=0;i<64;i++){let f,g,r=i>>>4;if(r===0){f=(c&d)|(~c&e);g=i}else if(r===1){f=(e&c)|(~e&d);g=(5*i+1)%16}else if(r===2){f=c^d^e;g=(3*i+5)%16}else{f=d^(c|~e);g=(7*i)%16}let next=(c+rol((a+f+mk[i]+m[g])|0,s[r][i%4]))|0;[a,c,d,e]=[e,next,c,d]}[a,c,d,e].forEach((x,i)=>h[i]=(h[i]+x)|0)}return output(h,true)}
function hmacMD5(key,msg){let k=key.length>64?md5(key):key.slice();while(k.length<64)k.push(0);return md5(k.map(x=>x^92).concat(md5(k.map(x=>x^54).concat(msg))))}
function signature(path,t,method='GET'){let m=hmacMD5(bytes('minikano_kOyXz0Ciz4V7wR0IeKmJFYFQ20jd'),bytes('minikano'+method+path+t));return hex(sha256(sha256(m.slice(0,8)).concat(sha256(m.slice(8)))))}

const C={ink:'#202124',muted:'#8B8B90',blue:'#A6833C',green:'#4C8E64',orange:'#B45D20',red:'#C94B4B',line:'#ECECEF',white:'#FFFFFF',gold:'#A6833C'};
const num=x=>x!==null&&x!==undefined&&x!==''&&Number.isFinite(Number(x))?Number(x):null;
const fmt=(x,d=0)=>x===null?'--':Number(x).toFixed(d);
const text=(v,size=11,color=C.ink,weight='regular',extra={})=>({type:'text',text:String(v??'--'),font:{size,weight},textColor:color,maxLines:1,minScale:0.72,...extra});
const stack=(direction,children,extra={})=>({type:'stack',direction,alignItems:'center',gap:3,children,...extra});
const row=(children,extra={})=>stack('row',children,extra);
const col=(children,extra={})=>stack('column',children,extra);
const icon=(name,color=C.muted,size=12,extra={})=>({type:'image',src:'sf-symbol:'+name,color,width:size,height:size,...extra});
const space=()=>({type:'spacer'});
const rule=()=>({type:'stack',direction:'row',children:[{type:'spacer'}],height:1,backgroundColor:C.line});
const pair=(name,value,color=C.blue,extra={})=>row([icon(name,color,11),text(value,11,C.ink)],{gap:2,...extra});
const svg=(mark,w,h)=>({type:'image',src:'data:image/svg+xml,'+mark,width:w,height:h});
function signal(n){
 const count=n===null?0:Math.max(0,Math.min(5,Math.round(n)));
 const marks=[4,7,10,13,16].map((h,i)=>"<rect x='"+(i*4.5)+"' y='"+(17-h)+"' width='3.3' height='"+h+"' rx='1' fill='"+(i<count?C.green:'#D9DDE2')+"'/>").join('');
 return svg("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 22 17'>"+marks+"</svg>",19,15);
}
function battery(n,charging){
 const pct=n===null?0:Math.max(0,Math.min(100,n)),color=n===null?C.muted:charging?C.green:C.ink;
 const bolt=charging?"<path d='M15 2L9 10H14L12 16L20 7H15Z' fill='#FFFFFF' stroke='"+color+"' stroke-width='0.35'/>":"";
 return svg("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 18'><rect x='1' y='2' width='27' height='14' rx='3' fill='none' stroke='"+color+"' stroke-width='1.5'/><rect x='29' y='6' width='2' height='6' rx='1' fill='"+color+"'/><rect x='3' y='4' width='"+(23*pct/100)+"' height='10' rx='1.5' fill='"+color+"'/>"+bolt+"</svg>",26,15);
}
function volume(v){
 const n=num(v);if(n===null||n<0)return '--';
 if(n>=1e9)return (n/1e9).toFixed(2)+' GB';
 if(n>=1e6)return (n/1e6).toFixed(2)+' MB';
 if(n>=1e3)return (n/1e3).toFixed(2)+' KB';
 return Math.round(n)+' B';
}
function rate(v,unit){const n=num(v);return n===null||n<0?'--':volume(unit==='bit'?n/8:n)+'/s'}
function duration(v){const n=num(v);if(n===null||n<0)return '--';const s=Math.floor(n);return [Math.floor(s/3600),Math.floor(s/60)%60,s%60].map(n=>String(n).padStart(2,'0')).join(':')}
const localTime=d=>[d.getHours(),d.getMinutes(),d.getSeconds()].map(n=>String(n).padStart(2,'0')).join(':');
// White compact native dashboard: typography is the hierarchy, not extra decoration.
const metric=(label,v)=>col([text(label,10,C.muted,'medium'),text(v,20,C.ink,'medium',{textAlign:'center'})],{flex:1,gap:2});
function speedLine(symbol,value){
 const color=value==='--'?C.muted:symbol==='arrow.down'?C.green:C.orange;
 const m=String(value).match(/^(.+?)\s+(\S+)$/);
 return row([icon(symbol,color,12),text(m?m[1]:value,18,color,'medium'),...(m?[text(m[2],10,color,'regular')]:[])],{gap:3,alignItems:'end'});
}
function layout(d,interval,refreshURL){
 const t=d.updated?localTime(new Date(d.updated)):'--:--:--';
 const refresh=icon('arrow.clockwise',C.muted,12,refreshURL?{url:refreshURL}:{});
 const bcolor=d.battery===null?C.muted:d.charging?C.green:C.ink;
 const line1=row([
   row([signal(d.bars),text(d.provider,14,C.ink,'semibold'),text(d.mode,11,C.muted,'medium'),text(d.band,11,C.muted,'medium')],{gap:4}),
   space(),
   row([icon('thermometer',C.muted,10),text(d.board===null?'--':fmt(d.board,1)+'°C',11,C.muted)],{gap:2}),
   row([battery(d.battery,d.charging),text(d.battery===null?'--':fmt(d.battery)+'%',14,bcolor,'medium')],{gap:2})
 ],{gap:4});
 const line2=row([
   col([speedLine('arrow.up',d.up),speedLine('arrow.down',d.down)],{flex:2.55,alignItems:'start',gap:0}),
   row([metric('RSRP',fmt(d.rsrp)),metric('RSRQ',fmt(d.rsrq)),metric('SINR',fmt(d.snr)),metric('PCI',fmt(d.pci))],{flex:4,gap:2})
 ],{gap:5});
 const usage=volume(d.today).match(/^(.+?)\s+(\S+)$/);
 const line3=row([
   row([icon('link',d.status==='已连接'?C.green:C.muted,10),text(d.status,10,d.status==='已连接'?C.green:C.muted,'medium')],{gap:2,padding:[3,5],borderRadius:7,backgroundColor:d.status==='已连接'?'#EAF3ED':'#F2F2F4'}),
   space(),pair('wifi',d.clients===null?'--':fmt(d.clients)+'台',C.muted),
   space(),row([icon('internaldrive',C.ink,11),text(usage?usage[1]:volume(d.today),15,C.ink,'medium'),...(usage?[text(usage[2],10,C.ink)]:[])],{gap:2}),
   space(),pair('clock',duration(d.connected),C.muted)
 ],{gap:2});
 const line4=row([
   row([icon('arrow.down',C.muted,10),text(d.dl===null?'--':fmt(d.dl)+' Mbps',10,C.ink)],{gap:2}),
   space(),row([icon('arrow.up',C.muted,10),text(d.ul===null?'--':fmt(d.ul)+' Mbps',10,C.ink)],{gap:2}),
   space(),text('QCI '+(d.qci===null?'--':fmt(d.qci)),10,C.muted),
   space(),row([text(t,10,C.muted),refresh],{gap:4})
 ],{gap:2});
 return {type:'widget',backgroundColor:C.white,padding:[10,12,10,12],gap:5,refreshAfter:new Date(Date.now()+interval*1000).toISOString(),children:[line1,line2,line3,rule(),line4]};
}
export default async function(ctx){
 const env=ctx.env||{},base='http://192.168.0.1:2333',password=String(env.UFI_PASSWORD||''),auth=hex(sha256(bytes(password)));
 const interval=Math.max(60,Math.min(3600,Number(env.REFRESH_INTERVAL)||300)),refreshURL=typeof env.REFRESH_URL==='string'&&env.REFRESH_URL.trim()?env.REFRESH_URL.trim():null,speedUnit=String(env.UFI_SPEED_UNIT||'byte').toLowerCase();
 const blank={provider:'--',band:'--',mode:'--',bars:null,battery:null,charging:false,board:null,rsrp:null,rsrq:null,snr:null,pci:null,up:'--',down:'--',status:'未获取',clients:null,today:null,connected:null,dl:null,ul:null,qci:null,updated:null};
 async function get(path,query='',signed=true){
   try{const t=String(Date.now()),headers={Accept:'application/json'};if(signed)Object.assign(headers,{'kano-t':t,'kano-sign':signature(path,t),authorization:auth});
     const r=await ctx.http.get(base+path+(query?'?'+query:''),{headers,timeout:6500,policy:'DIRECT',redirect:'error',credentials:'omit'});
     if(Number(r.status)!==200)return null;const d=JSON.parse(await r.text());return d&&typeof d==='object'&&!d.error?d:null;
   }catch{return null}
 }
 const [version,need]=await Promise.all([get('/api/version_info','',false),get('/api/need_token','',false)]);
 if(!version||!need||!/U30\s*Air/i.test(version.model||''))return layout({...blank,status:'设备不可达'},interval,refreshURL);
 if(need.need_token&&!password)return layout({...blank,status:'缺少密码'},interval,refreshURL);
 const go=(cmd,multi=true)=>get('/api/goform/goform_get_cmd_process','isTest=false&'+(multi?'multi_data=1&':'')+'cmd='+encodeURIComponent(cmd)+'&_='+Date.now());
 const [info,radio,network,traffic]=await Promise.all([get('/api/baseDeviceInfo'),go('network_provider,network_type,network_signalbar,ppp_status,sim_slot,battery_charging,battery_value,wifi_access_sta_num'),go('network_information',false),go('flux_realtime_rx_thrpt,flux_realtime_tx_thrpt,realtime_rx_thrpt,realtime_tx_thrpt,realtime_time')]);
 if(!info&&!radio&&!network&&!traffic)return layout({...blank,status:'采集失败'},interval,refreshURL);
 let n=network?.network_information??network??{};if(typeof n==='string'){try{n=JSON.parse(n)}catch{n={}}}
 const r=radio||{},b=info||{},f=traffic||{};
 const at=async(command,slot,label)=>{
   const d=await get('/api/AT','command='+encodeURIComponent(command)+'&slot='+slot),raw=typeof d?.result==='string'?d.result:'';
   const m=raw.match(new RegExp('\\+'+label+':\\s*([^\\r\\n]*?)(?:\\s+OK\\b|\\s+ERROR\\b|$)','i'));
   return m&&!/\bERROR\b/i.test(raw)?m[1].split(',').map(x=>x.trim()):null;
 };
 const reported=num(r.sim_slot);let slot=reported===0||reported===1?reported:1;
 let operator=await at('AT+COPS?',slot,'COPS');
 if(num(operator?.[3])===null){const alt=1-slot,other=await at('AT+COPS?',alt,'COPS');if(num(other?.[3])!==null){slot=alt;operator=other}}
 const act=num(operator?.[3]),qos=act===null?null:await at('AT+CGEQOSRDP=1',slot,'CGEQOSRDP'),q=Array.isArray(qos)&&qos.length===8?qos.map(num):null,validQ=q&&q.every(x=>x!==null&&x>=0);
 const ppp=String(r.ppp_status||''),connected=/^(?:ipv4_ipv6_connected|ipv4_connected|ipv6_connected|connected)$/i.test(ppp);
 const mode=act===11&&num(n.network_type)===20?'5G SA':act===13?'5G NSA':String(r.network_type||'--');
 const nrBand=String(n.Nr_bands??''),lteBand=String(n.Lte_bands??''),rawBand=nrBand||lteBand,band=rawBand.split(/[,;\s]+/).filter(x=>/^\d+$/.test(x)).map(x=>(nrBand?'n':'B')+x).join('+')||'--';
 const board=num(b.cpu_temp_list?.find?.(x=>x.type==='board-thmzone')?.temp);
 const d={provider:String(r.network_provider||'--'),band,mode,bars:num(r.network_signalbar),battery:num(b.battery)??num(r.battery_value),charging:String(r.battery_charging)==='1',board:board===null?null:board/1000,rsrp:num(n.nr_rsrp),rsrq:num(n.nr_rsrq),snr:num(n.Nr_snr),pci:num(n.Nr_pci),up:rate(num(f.flux_realtime_tx_thrpt)??num(f.realtime_tx_thrpt),speedUnit),down:rate(num(f.flux_realtime_rx_thrpt)??num(f.realtime_rx_thrpt),speedUnit),status:connected?'已连接':ppp?'未连接':'--',clients:num(r.wifi_access_sta_num),today:num(b.daily_data),connected:num(f.realtime_time),dl:validQ?q[6]/1000:null,ul:validQ?q[7]/1000:null,qci:validQ?q[1]:null,updated:new Date().toISOString()};
 return layout(d,interval,refreshURL);
}
