/**
 * Weibo Ads Safe V1.2.5 — native Egern response filter.
 * Based on online V1.2.3 and user-supplied V1.2.4. References: fmz200, zmqcherish, RuCu6, ddgksf2013.
 * Explicit ad evidence; protect followed author post subtrees on home timelines.
 * Unknown generic containers, account/publication endpoints, malformed/error responses pass through.
 * No recursive blanket cleanup of user objects, normal detail recommendations or search hints.
 */
const WEB_API_HOSTS=new Set(["api.weibo.cn","api.weibo.com","mapi.weibo.cn","mapi.weibo.com"]);
const LIST_KEYS=new Set(["items","statuses","datas","cards","card_group","comments","comments_list","comment_list","commentList","list","resultList","feeds","feed","sections","contents","mblog_list","status_list","head_cards","top_cards","header_cards","channels","groups","reposts","hot_reposts","data"]);
const NEST_KEYS=new Set(["data","result","payload","status","mblog","card","pageHeader","detailInfo","item","container","feed","comment","timeline","main","head","body","tab","content","dataInfo","channelInfo","header","insert_data"]);
const EXPLICIT_AD_TYPES=new Set(["ad","ads","advertisement","commercial","sponsored","sponsor","feed_ad","native_ad","ad_card","promoted_ad","promoted_post"]);
const STRONG_FEED_MODES=new Set(["feed","discovery","search","video"]);
const HOME_TIMELINE_PATH=/^\/2\/(?:statuses\/(?:friends\/(?:timeline|mix_timeline)|friends_timeline|unread_friends(?:_timeline|\/timeline)|unread_hot_timeline|container_timeline(?:_hot|_unread)?)|groups\/timeline)\/?$/;
const GENERIC=/^\/2\/(?:cardlist|container\/get_item|page|flowpage)\/?$/;
const PROTECTED_PATH=/\/(?:statuses\/(?:update|upload|send|create|edit|destroy|share|repost|comment|publish)|(?:compose|composer|publisher|publish|draft|drafts|upload|uploads|media\/upload|photo\/upload|login|logout|account|oauth|payment|pay|order|verify|verification))(?:\/|$)/i;
const ROUTES=[["feed",/^\/(?:statuses\/(?:friends\/(?:timeline|mix_timeline)|friends_timeline|unread_friends(?:_timeline|\/timeline)|unread_hot_timeline|container_timeline(?:_hot|_unread|_topic|_topicpage)?|repost_timeline)|guest\/container_timeline_hot|groups\/timeline)\/?$/],
["comments",/^\/(?:comments\/(?:mix_comments|build_comments|hotflow)|statuses\/(?:container_detail_comment|container_detail_mix|container_detail_forward))\/?$/],
["detail",/^\/statuses\/(?:container_detail|extend|show)\/?$/],
["discovery",/^\/search\/(?:finder|container_timeline|container_discover)\/?$/],
["search",/^\/searchall\/?$/],
["video",/^\/(?:video\/(?:flow_stream|flow_stream_cache|tiny_stream_video_list|community_tab|full_screen_stream)|statuses\/video_mixtimeline)\/?$/],
["profile",/^\/profile\/me\/?$/],
["messages",/^\/messageflow(?:\/notice)?\/?$/]];
const DEBUG=false;

function obj(v){return v!==null&&typeof v==='object'&&!Array.isArray(v);}

function flagged(v){return v===true||v===1||v==='1'||v==='true';}

function adType(v){return typeof v==='string'&&EXPLICIT_AD_TYPES.has(v.trim().toLowerCase());}

function adLabel(v){return typeof v==='string'&&/^(?:广告|商业广告|广告微博|推广广告|广告推荐)$/u.test(v.trim());}

function validMarker(v,depth=0){
  if(depth>3||v==null||v===false)return false;
  if(typeof v==='boolean')return v;
  if(typeof v==='number')return Number.isFinite(v)&&v>0;
  if(typeof v==='string')return !/^(?:|0|false|null|undefined)$/i.test(v.trim());
  if(Array.isArray(v))return v.some(x=>validMarker(x,depth+1));
  return obj(v)&&Object.values(v).some(x=>validMarker(x,depth+1));
}

function adId(v){return (typeof v==='string'||typeof v==='number')&&validMarker(v);}

function hasAdPromotion(v){
  if(flagged(v))return true;
  if(!obj(v))return false;
  return ['is_ad','is_ads','isAd','isAds'].some(k=>flagged(v[k]))||
    ['type','ad_type','promotion_type'].some(k=>adType(v[k]))||
    ['adid','ad_id'].some(k=>adId(v[k]))||
    (Array.isArray(v.monitor_url)&&v.monitor_url.some(x=>typeof x==='string'&&/^https?:\/\//i.test(x)))||
    adLabel(v.mark)||adLabel(v.display_text);
}

function adCandidates(item){
  if(!obj(item))return [];
  return [item,item.data,item.status,item.mblog,item.card,item.data?.mblog,item.data?.status,item.data?.card,item.card?.mblog,item.card?.data,item.card?.data?.mblog,item.card?.data?.status].filter(obj);
}

function looksLikePost(x){
  return obj(x)&&(typeof x.text==='string'||typeof x.text_raw==='string'||x.mid!=null||x.mblogtype!=null||
    (obj(x.user)&&(x.id!=null||x.idstr!=null||x.created_at!=null)));
}

function actualPost(item){
  if(!obj(item))return null;
  // Named post wrappers take priority over unrelated card users.
  for(const x of [item.mblog,item.status,item.data?.mblog,item.data?.status,item.card?.mblog,item.card?.data?.mblog,item.card?.data?.status])
    if(obj(x))return x;
  for(const x of [item,item.data,item.card?.data,item.card])if(looksLikePost(x))return x;
  return null;
}

function isFollowedAuthorPost(item){const post=actualPost(item);return !!(post&&obj(post.user)&&flagged(post.user.following));}

function isCardContainer(item){
  if(!obj(item))return false;
  return [item,item.data,item.card,item.card?.data].some(x=>obj(x)&&Array.isArray(x.card_group));
}

function isClearlyAd(item,mode){
  for(const d of adCandidates(item)){
    if(STRONG_FEED_MODES.has(mode)&&(d.mblogtype===1||d.mblogtype==='1'))return true;
    if(['is_ad','is_ads','isAd','isAds','isAliMaMaAD'].some(k=>flagged(d[k])))return true;
    if(flagged(d.ad_state))return true;
    if([d.mblogtypename,d.adType,d.commentAdType,d.content_auth_info?.content_auth_title].some(adLabel))return true;
    if(['category','model_type','card_type','cardType','bizType','ad_type'].some(k=>adType(d[k])))return true;
    if(hasAdPromotion(d.promotion)||hasAdPromotion(d.promotion_info))return true;
    if(obj(d.ads_material_info)&&(flagged(d.ads_material_info.is_ads)||flagged(d.ads_material_info.is_ad)))return true;
    if(typeof d.itemid==='string'&&/(?:^|[&_:])is_ad_pos(?:[&_:]|$)/i.test(d.itemid))return true;
  }
  return false;
}

function queryPairs(query){
  try{return query.split('&').filter(Boolean).map(s=>{const i=s.indexOf('=');return [decodeURIComponent(i<0?s:s.slice(0,i)).toLowerCase(),decodeURIComponent(i<0?'':s.slice(i+1)).replace(/\+/g,' ')];});}
  catch(_){return null;}
}

function genericScene(query){
  const pairs=queryPairs(query);
  if(!pairs)return false;
  // Unknown/ambiguous generic routes pass through. No profile/UID containers.
  if(pairs.some(([k,v])=>/^(?:uid|user_id|profile_uid|target_uid)$/.test(k)&&v!==''&&v!=='0'))return false;
  const ids=pairs.filter(([k])=>/^(?:containerid|container_id|page_id)$/.test(k)).map(([,v])=>v);
  return ids.length>0&&ids.every(v=>/^(?:100103(?:type=|$)|106003(?:type=|$))/.test(v));
}

function readRoute(rawUrl){
  const m=/^https?:\/\/([a-z0-9.-]+)(?::(?:443|80))?(\/[^?#]*)(?:\?([^#]*))?(?:#.*)?$/i.exec(rawUrl);
  if(!m)return null;
  const host=m[1].toLowerCase(),path=m[2],query=m[3]||'';
  if(PROTECTED_PATH.test(path))return null;
  if((host==='bootpreload.uve.weibo.com'||host==='boot.biz.weibo.com')&&/^\/v\d+\/ad\/preload\/?$/.test(path))return {type:'splash',path};
  if((host==='bootrealtime.uve.weibo.com'||host==='boot.biz.weibo.com')&&/^\/v\d+\/ad\/realtime\/?$/.test(path))return {type:'splash',path};
  if(host==='sdkapp.uve.weibo.com'&&/^\/interface\/sdk\/sdkad\.php\/?$/.test(path))return {type:'splash',path};
  if(host==='wbapp.uve.weibo.com'&&/^\/(?:wbapplua\/wbpullad\.lua|preload\/get_ad)\/?$/.test(path))return {type:'splash',path};
  if(!WEB_API_HOSTS.has(host)||!path.startsWith('/2/'))return null;
  if(GENERIC.test(path))return genericScene(query)?{type:'search',path}:null;
  const route=ROUTES.find(([,re])=>re.test(path.slice(2)));
  return route?{type:route[0],path}:null;
}

function clearSplash(x){
  if(!obj(x))return 0;
  let n=0;
  for(const k of ['ads','ad','ad_list','ads_list','ads_groups','bidding_ads','splash_ads','feed_ad_arr']){
    if(Array.isArray(x[k])&&x[k].length){x[k]=[];n++;}
  }
  if(obj(x.adMap)&&Object.keys(x.adMap).length){x.adMap={};n++;}
  for(const k of ['cacheAdInfo','realTimeAd'])if(Object.prototype.hasOwnProperty.call(x,k)&&x[k]!==null){x[k]=null;n++;}
  if(flagged(x.show_push_splash_ad)){x.show_push_splash_ad=false;n++;}
  if(flagged(x.display_ad)){x.display_ad=0;n++;}
  if(typeof x.background_delay_display_time==='number'&&x.background_delay_display_time<31536000){x.background_delay_display_time=31536000;n++;}
  return n;
}

function cleanSplash(root){
  let n=0;
  for(const x of [root,root.data,root.data?.data,root.cached_ad,root.data?.cached_ad,root.data?.splash,root.data?.splash_ad])n+=clearSplash(x);
  return n;
}

function cleanMessages(root){
  let n=0;
  for(const x of [root,root.data]){
    if(!obj(x)||!Array.isArray(x.messages))continue;
    const next=x.messages.filter(m=>!validMarker(m?.msg_card?.ad_tag));
    n+=x.messages.length-next.length;
    if(next.length!==x.messages.length)x.messages=next;
  }
  return n;
}

function cleanFeed(root,mode,path){
  const preserveFollowed=mode==='feed'&&HOME_TIMELINE_PATH.test(path);
  let changes=0,visited=0;
  function protectedPost(x){return preserveFollowed&&isFollowedAuthorPost(x);}
  function walk(node,depth){
    if(!obj(node)||depth>8||visited>=9000||protectedPost(node))return;
    visited++;
    for(const [key,value] of Object.entries(node)){
      if(Array.isArray(value)&&LIST_KEYS.has(key)){
        const kept=[];
        for(const item of value){
          if(protectedPost(item)){kept.push(item);continue;}
          // Walk containers even with one child; never remove by parent marker alone.
          if(!isCardContainer(item)&&isClearlyAd(item,mode)){changes++;continue;}
          if(obj(item))walk(item,depth+1);
          kept.push(item);
        }
        if(kept.length!==value.length)node[key]=kept;
      }else if(obj(value)&&NEST_KEYS.has(key))walk(value,depth+1);
    }
  }
  walk(root,0);
  if(['feed','discovery','search','video','profile','detail'].includes(mode)){
    for(const x of [root,root.data]){
      if(!obj(x)||protectedPost(x))continue;
      for(const k of ['ad','ads','ad_list','ads_list','advertises','advertisements','feed_ad_arr']){
        if(!Array.isArray(x[k])||!x[k].length)continue;
        const kept=preserveFollowed?x[k].filter(protectedPost):[];
        if(kept.length!==x[k].length){changes++;x[k]=kept;}
      }
    }
  }
  return changes;
}

export default async function handle(ctx){
  const rawUrl=ctx?.request?.url;
  if(typeof rawUrl!=='string'||!ctx?.response)return;
  const route=readRoute(rawUrl);
  if(!route)return;
  const method=typeof ctx.request.method==='string'?ctx.request.method.toUpperCase():'';
  if(method!=='GET'&&method!=='POST')return;
  if(typeof ctx.response.status==='number'&&(ctx.response.status<200||ctx.response.status>=300))return;
  let raw;
  try{raw=await ctx.response.text();}catch(_){return;}
  if(typeof raw!=='string'||!raw.trim())return;
  try{
    const suffix=/sdkad\.php\/?$/.test(route.path)&&/}\s*OK\s*$/.test(raw)?'OK':'';
    const jsonText=suffix?raw.slice(0,raw.lastIndexOf('OK')).trimEnd():raw;
    const root=JSON.parse(jsonText);
    if(!obj(root)||root.ok===0||root.ok==='0'||root.success===false||root.error||root.error_code)return {body:raw};
    const n=route.type==='splash'?cleanSplash(root):route.type==='messages'?cleanMessages(root):cleanFeed(root,route.type,route.path);
    if(!n)return {body:raw};
    if(DEBUG)console.log('[Weibo Safe V1.2.5] '+route.type+' changes='+n);
    return {body:JSON.stringify(root)+suffix};
  }catch(_){return {body:raw};}
}
