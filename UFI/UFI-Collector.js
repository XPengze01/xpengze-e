// UFI Collector 0.4 — Egern generic script, read-only, no widget layout.
// UFI-TOOLS API v4.1.3; target U30 Air v4.1.6 (device verification pending).
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
function signature(path,t){let m=hmacMD5(bytes('minikano_kOyXz0Ciz4V7wR0IeKmJFYFQ20jd'),bytes('minikanoGET'+path+t));return hex(sha256(sha256(m.slice(0,8)).concat(sha256(m.slice(8)))))}
function safe(v){if(Array.isArray(v))return v.map(safe);if(v&&typeof v==='object'){const out={};for(const [k,x] of Object.entries(v)){if(/password|passwd|token|authorization|cookie|imei|imsi|iccid|msisdn|phone|mac_address|client_ip|wan_ip|ip_address|ipv4_address|ipv6_address|device_id|secret|credential|username|private_key|wifi_key|sim_pin|sim_puk|gps|latitude|longitude|uuid|serial|hostname|(^|_)mac($|_)|(^|_)ssid($|_)|cell_?id|(^|_)tac($|_)|(^|_)lac($|_)|neighbor_cell|locked_cell|network_information/i.test(k)&&k!=='need_token'){out[k]='[redacted]';continue}out[k]=safe(x)}return out}if(typeof v==='string'){if(/^\s*[\[{]/.test(v)){try{return JSON.stringify(safe(JSON.parse(v)))}catch{}}return v.replace(/(?:[0-9a-f]{2}:){5}[0-9a-f]{2}/gi,'[MAC redacted]').replace(/\b\d{14,22}\b/g,'[identifier redacted]')}return v}
const groups={
 radio:'network_type,network_provider,ppp_status,network_signalbar,network_rssi,rssi,Z5g_rsrp,lte_rsrp,Lte_ca_status,dual_sim_support,sim_slot',
 battery:'battery_charging,battery_value,battery_vol_percent,usb_port_switch',
 traffic:'realtime_rx_thrpt,realtime_tx_thrpt,realtime_time,monthly_tx_bytes,monthly_rx_bytes,monthly_time,flux_data_volume_limit_switch,data_volume_limit_switch,data_volume_limit_unit,data_volume_limit_size,data_volume_alert_percent,wan_auto_clear_flow_data_switch,traffic_clear_date',
 wifi:'wifi_access_sta_num,queryWiFiModuleSwitch,lan_netmask,dhcpEnabled,dhcpLease_hour,mtu,tcp_mss',
 bands:'lte_band_lock,nr_band_lock',
 switches:'performance_mode,net_select,usb_network_protocal,samba_switch,roam_setting_option,dial_roam_setting_option,indicator_light_switch,restart_schedule_switch,restart_time,sleep_sysIdleTimeToSleep,is_support_nfc_functions,web_wifi_nfc_switch',
 firmware:'cr_version,wa_inner_version,Language',
 experimental:'Z5g_sinr,Z5g_rsrq,lte_snr,lte_rsrq,lte_sinr,lte_pci,nr_pci,Z5g_pci,Z5g_band,lte_band,nr_band,nr_arfcn,lte_earfcn,cell_id,network_information'
};
export default async function(ctx){
 const report={collector:'0.4',time:new Date().toISOString(),results:{},notes:[]};
 const base='http://192.168.0.1:2333';
 const password=ctx.env?.UFI_PASSWORD||'';
 const auth=hex(sha256(bytes(password)));
 report.passwordConfigured=!!password;
 const errText=e=>{let t=String(e?.message||e||'unknown error');for(const x of [password,auth])if(x)t=t.split(x).join('[redacted]');return t.replace(/[a-f0-9]{32,}/gi,'[redacted]').slice(0,220)};
 const log=(s)=>{try{if(typeof console!=='undefined'&&typeof console.log==='function')console.log(s)}catch{}};
 async function get(path,query='',extra={},signed=true){
   let resp;try{
     const t=String(Date.now());const headers={Accept:'application/json',...extra};
     if(signed)Object.assign(headers,{'kano-t':t,'kano-sign':signature(path,t),authorization:auth});
     resp=await ctx.http.get(base+path+(query?'?'+query:''),{headers,timeout:7000,policy:'DIRECT',redirect:'error',credentials:'omit'});
   }catch(e){return {ok:false,stage:'http_request',error:errText(e)}}
   const status=Number(resp.status);
   if(status!==200)return {status,ok:false,stage:'http_status'};
   try{const data=JSON.parse(await resp.text());return {status,ok:!!data&&typeof data==='object'&&!data.error,data};}
   catch(e){return {status,ok:false,stage:'json_parse',error:errText(e)}}
 }
 const record=(name,r)=>{report.results[name]=safe(r);log('UFI '+name+' '+JSON.stringify(report.results[name]));};
 const complete=()=>{
   const count=Object.values(report.results).filter(r=>r.ok).length;
   log('UFI notes '+JSON.stringify(report.notes));
   try{ctx.storage.setJSON('ufi_collector_latest',report)}catch(e){log('storage '+errText(e))}
   const lines=Object.entries(report.results).map(([k,r])=>k+': '+(r.ok?'OK':(r.status?'HTTP '+r.status:r.stage||'failed'))+(r.error?' '+r.error:''));
   const summary='UFI 0.4 | '+count+'/'+Object.keys(report.results).length+'\n'+lines.slice(0,5).join('\n')+'\n'+report.notes.join('\n');
   try{ctx.notify({title:'UFI Collector 0.4',body:summary,sound:false,action:{type:'clipboard',text:JSON.stringify(report,null,2)}})}catch(e){log('notification '+errText(e))}
   return {type:'widget',children:[{type:'text',text:summary+'\n\n'+JSON.stringify(report,null,2)}]};
 };
 const cryptoOK=hex(sha256(bytes('abc')))==='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'&&hex(md5(bytes('abc')))==='900150983cd24fb0d6963f7d28e17f72'&&hex(hmacMD5(bytes('key'),bytes('The quick brown fox jumps over the lazy dog')))==='80070713463e7749b90c2dc24911e275';
 record('crypto_selftest',{ok:cryptoOK});
 if(!cryptoOK){report.notes.push('签名算法自检失败');return complete()}
 const v=await get('/api/version_info','',{},false);record('version',v);const n=await get('/api/need_token','',{},false);record('auth_required',n);
 if(!v.ok||!n.ok){report.notes.push('无法确认局域网设备或鉴权状态');return complete()}
 if(n.data.need_token&&!password){report.notes.push('需要填写 UFI_PASSWORD');return complete()}
 if(!/U30\s*Air/i.test(v.data.model||'')){report.notes.push('型号非 U30 Air，停止发送鉴权请求');return complete()}
 const info=await get('/api/baseDeviceInfo');record('base',info);if(!info.ok){report.notes.push('基础接口失败；如为401，请核对密码及设备时间');return complete()}
 const now=Date.now(),month=new Date();month.setDate(1);month.setHours(0,0,0,0);const week=new Date();week.setDate(week.getDate()-6);week.setHours(0,0,0,0);
 const queries=[['connections','/api/connInfo'],['data_limit','/api/get_data_limit'],['usb','/api/usb_status'],['selinux','/api/SELinux'],['volte','/api/volte_status','slot=0'],['vonr','/api/vonr_status','slot=0'],['usage_month','/api/cellularUsage','startTime='+month.getTime()+'&endTime='+now+'&method=date-range'],['usage_7days','/api/cellularUsage','startTime='+week.getTime()+'&endTime='+now+'&method=date-range']];
 for(let i=0;i<queries.length;i+=3)await Promise.all(queries.slice(i,i+3).map(async ([name,p,q])=>record(name,await get(p,q))));
 // Reuse the existing official web session ONLY in memory. Never log or store the cookie.
 const ck=await get('/api/get_cookie');let cookie=ck.ok&&typeof ck.data.cookie==='string'?ck.data.cookie:'';let extra=cookie?{'kano-cookie':cookie}:{};
 const go=(cmd)=>get('/api/goform/goform_get_cmd_process','isTest=false&multi_data=1&cmd='+encodeURIComponent(cmd)+'&_='+Date.now(),extra);
 const login=await go('loginfo');record('official_session',login);if(login.data?.loginfo!=='ok')report.notes.push('官方会话未确认；仍尝试公开状态字段。若缺失，请先在 UFI 后台进入中兴官方管理页面登录后再运行。');
 // Probe network_information on its own, before other signal queries.
 // Some firmware returns a flat object rather than the requested command key.
 const present=x=>x!==undefined&&x!==null&&x!==''&&x!=='[redacted]'&&x!=='--';
 const signalKey=k=>/^(?:network_|nr_|nr5g_|lte_|z5g_|5g_|zcellinfo_|z_|wan_active_|wan_lte_ca|endc|nsa|sa_|rat|rsrp|rsrq|sinr|rssi|snr|pci|band|arfcn|earfcn|cqi|mcs|dl_|ul_|mcc|mnc)/i.test(k)&&!/(?:password|passwd|pwd|secret|token|cookie|key|imei|imsi|iccid|msisdn|phone|mac|cell_?id|enodeb|gnodeb|(?:^|_)tac(?:$|_)|(?:^|_)lac(?:$|_)|(?:^|_)ip(?:$|_)|apn|url|name|location|gps|latitude|longitude|lock|neighbor)/i.test(k);
 function signalDump(data){
   const fields={},otherKeys=[];
   function visit(obj,prefix='',depth=0){
     if(depth>4||!obj||typeof obj!=='object')return;
     for(const [key,value] of Object.entries(obj)){
       if(/password|passwd|pwd|secret|token|cookie|imei|imsi|iccid|msisdn|phone|mac|cell_?id|enodeb|gnodeb|(?:^|_)tac(?:$|_)|(?:^|_)lac(?:$|_)|apn|location|gps|latitude|longitude/i.test(key))continue;
       if(key==='network_information'||(value&&typeof value==='object'&&!Array.isArray(value))){
         let inner=value;if(typeof inner==='string'){try{inner=JSON.parse(inner)}catch{inner=null}}
         if(inner&&typeof inner==='object')visit(inner,prefix+key+'.',depth+1);
         else otherKeys.push(prefix+key);continue;
       }
       if(signalKey(key)&&(['number','boolean'].includes(typeof value)||(typeof value==='string'&&value.length<=180)))fields[prefix+key]=value;
       else otherKeys.push(prefix+key);
     }
   }
   visit(data);return {fields,otherKeys,nonempty:Object.keys(fields).filter(k=>present(fields[k]))};
 }
 async function standalone(name,multi,viaDirect=false){
   const q='isTest=false&cmd=network_information'+(multi===null?'':'&multi_data='+multi)+'&_='+Date.now();
   let r;
   if(!viaDirect)r=await get('/api/goform/goform_get_cmd_process',q,extra);
   else {try{const resp=await ctx.http.get('http://192.168.0.1/goform/goform_get_cmd_process?'+q,{headers:{Accept:'application/json',Referer:'http://192.168.0.1/index.html'},timeout:7000,policy:'DIRECT',redirect:'error',credentials:'omit'});const status=Number(resp.status);r=status===200?{status,ok:true,data:JSON.parse(await resp.text())}:{status,ok:false};}catch(e){r={ok:false,stage:'direct_request',error:errText(e)}}}
   if(r.ok){const d=signalDump(r.data);r={status:r.status,ok:d.nonempty.length>0,data:d.fields,returned:Object.keys(d.fields),nonempty:d.nonempty,otherKeys:d.otherKeys};}
   record(name,r);return r;
 }
 const dumps=[];
 dumps.push(await standalone('deep_network_single',null));
 if(!dumps[0].ok)dumps.push(await standalone('deep_network_multi',1));
 if(!dumps.some(r=>r.ok))dumps.push(await standalone('deep_network_direct',null,true));
 const entries=Object.entries(groups);for(let i=0;i<entries.length;i+=2)await Promise.all(entries.slice(i,i+2).map(async ([name,cmd])=>{const r=await go(cmd);if(r.ok){const keys=cmd.split(',');const returned=keys.filter(k=>Object.prototype.hasOwnProperty.call(r.data,k));const nonempty=returned.filter(k=>r.data[k]!==''&&r.data[k]!==null&&r.data[k]!==undefined);r.returned=returned;r.nonempty=nonempty;r.missing=keys.filter(k=>!returned.includes(k));if(!nonempty.length)r.ok=false;
 r.data=Object.fromEntries(returned.map(k=>[k,r.data[k]]));}record('zte_'+name,r)}));
 // Probe documented aliases in short batches; preserve zero as an actual value.
 const probes={
 deep_nr_signal:'Z5g_SINR,Z5g_snr,Z5g_rsrq,Z5g_rssi,5g_sinr,nr5g_sinr,5g_rsrp,nr5g_rsrp',
 deep_nr_active:'nr5g_action_band,nr5g_action_channel,nr5g_pci,network_ZCELLINFO_band,network_Z5g_PCI,network_Z5g_rsrp,network_Z5g_rsrq,network_Z5g_SINR',
 deep_network_mode:'network_type,network_mode,network_rat,network_sinr,network_rsrq,network_rssi,nr5g_mode,network_type_ex,wan_lte_ca,endc_status,net_select_mode',
 deep_lte_active:'wan_active_band,wan_active_channel,lte_ca_pcell_band,lte_ca_pcell_bandwidth,lte_ca_pcell_arfcn,lte_ca_scell_band,lte_ca_scell_bandwidth,lte_ca_scell_arfcn,network_lte_rsrp,network_lte_rsrq,network_lte_snr',
 deep_nr_details:'Nr_bands,Nr_snr,Nr_pci,nr_rsrp,nr_rsrq,Nr_arfcn,Nr_bandwidth,nr_sinr,nr_rssi,nr_cqi',
 deep_thermal:'battery_temperature,battery_temp,battery_health,battery_cycle_count,battery_capacity,battery_pers,pm_sensor_pa1,pm_sensor_ambient,pm_sensor_mdm,pm_modem_5g,pm_sensor_5g',
 deep_wifi:'wifi_mode,wifi_band,wifi_channel,wifi_bandwidth,wifi_5g_channel,wifi_2g_channel,wifi_5g_bandwidth,wifi_2g_bandwidth,wifi_5g_access_sta_num,wifi_2g_access_sta_num,wifi_max_access_num',
 deep_counters:'realtime_tx_bytes,realtime_rx_bytes,flux_monthly_tx_bytes,flux_monthly_rx_bytes,flux_realtime_tx_thrpt,flux_realtime_rx_thrpt,wan_connect_status,monthly_time',
 deep_config:'model_name,hardware_version,web_version,simcard_status,network_simcard_roam,rmcc,rmnc,mdm_mcc,mdm_mnc,ppp_status'
 };
 const deepData={};for(const d of dumps)if(d.ok)Object.assign(deepData,d.data);
 const probeEntries=Object.entries(probes);
 for(let i=0;i<probeEntries.length;i+=2)await Promise.all(probeEntries.slice(i,i+2).map(async ([name,cmd])=>{
    const r=await go(cmd);if(r.ok){const returned=Object.keys(r.data).filter(k=>cmd.split(',').includes(k));const data=Object.fromEntries(returned.map(k=>[k,r.data[k]]));const nonempty=returned.filter(k=>present(data[k]));Object.assign(deepData,Object.fromEntries(nonempty.map(k=>[k,data[k]])));record(name,{status:r.status,ok:nonempty.length>0,data,returned,nonempty,missing:cmd.split(',').filter(k=>!returned.includes(k))});}else record(name,r);
 }));
 // AT commands are a fixed read-only allowlist. Never execute user-provided commands.
 // Run modem commands serially; retain response shape but redact long IDs and quoted registration identifiers.
 const slotRaw=report.results.zte_radio?.data?.sim_slot;const slot=String(slotRaw)==='2'?1:0;
 const atCommands=[['at_nr_serving','AT+SPENGMD=0,14,1'],['at_lte_serving','AT+SPENGMD=0,6,0'],['at_operator','AT+COPS?'],['at_nr_registration','AT+C5GREG?'],['at_lte_registration','AT+CEREG?'],['at_extended_quality','AT+CESQ'],['at_basic_quality','AT+CSQ']];
 for(const [name,command] of atCommands){
   const r=await get('/api/AT','command='+encodeURIComponent(command)+'&slot='+slot);
   if(r.ok){
     const raw=typeof r.data.result==='string'?r.data.result:'';
     const cleaned=raw.replace(/"([0-9a-f]{4,})"/gi,'"[id redacted]"').replace(/\b(?:0x[0-9a-f]{5,}|[0-9a-f]{8,})\b/gi,'[id redacted]').replace(/\b\d{7,}\b/g,'[long number redacted]');
     record(name,{status:r.status,ok:!!raw&&!/\bERROR\b/i.test(raw)&&/\+[\w]+:/.test(raw),data:{command,slot,result:cleaned.slice(0,4500)}});
   }else record(name,{status:r.status,ok:false,stage:r.stage,error:r.error,command,slot});
   if(r.stage==='http_request'){report.notes.push('AT 查询出现网络异常，停止后续 AT 请求以免重复占用基带');break}
 }
 record('supported_nr_bands',await get('/api/getSupportNrBandList','slot='+slot));
 if(slot===0){record('volte_slot2',await get('/api/volte_status','slot=1'));record('vonr_slot2',await get('/api/vonr_status','slot=1'))}
 // List candidates by exact source field. Do not infer SA from 5G, or active band from a lock list.
 const allRadio={...report.results.zte_radio?.data,...deepData};
 const pick=(patterns)=>Object.entries(allRadio).filter(([k,v])=>present(v)&&patterns.some(p=>p.test(k))).map(([field,value])=>({field,value}));
 report.priorityFields={
   activeBandCandidates:pick([/(?:^|\.)(?:Nr_bands|nr5g_action_band|network_ZCELLINFO_band|wan_active_band|lte_ca_pcell_band)$/i]),
   modeCandidates:pick([/(?:^|\.)(?:network_type|network_mode|network_rat|network_type_ex|nr5g_mode|endc_status)$/i]),
   sinrCandidates:pick([/(?:sinr|snr)$/i]),
   rsrqCandidates:pick([/rsrq$/i]),
   rsrpCandidates:pick([/rsrp$/i]),
   pciCandidates:pick([/pci$/i]),
   channelCandidates:pick([/(?:arfcn|action_channel|active_channel)$/i])
 };
 report.notes.push('优先字段是原始候选值，SA/NSA及AT字段含义待真机结果确认；频段锁定列表不视为在用频段。AT 原始响应的长数字/注册标识已部分遮盖，分享前可再检查。');
 cookie='';extra={};return complete();
}
