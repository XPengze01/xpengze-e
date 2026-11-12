/**
 * Weibo Ads Safe V1.2.0 — Egern native response-only script.
 * Inspired by publicly documented ad markers from fmz200, zmqcherish,
 * RuCu6 and ddgksf2013 WeiboEnhanced; independently implemented.
 *
 * Invariants:
 * 1) No HTTP request rewrite, no host-wide REJECT, no traffic replay.
 * 2) Publish/upload/draft/login/payment paths are not on the allowlist.
 * 3) Feed-only aggressive filtering of promotion and promotion_info fields.
 * 4) JSON parse failures, non-2xx responses and exceptions pass through.
 * 5) Feed promoted recommendations may be hidden; ordinary posts/comments are retained.
 * 6) All ad categories are on by default; no settings/environment controls.
 * 7) For messageflow, only remove msg_card.ad_tag, not normal messages.
 */

const WEB_API_HOSTS = new Set(['api.weibo.cn', 'api.weibo.com', 'mapi.weibo.cn', 'mapi.weibo.com']);
const STRONG_FEED_MODES = new Set(['feed', 'discovery', 'search', 'video', 'profile']);
const ROUTES = [
  { type: 'feed', key: 'FEED', re: /^\/(?:statuses\/(?:friends\/(?:timeline|mix_timeline)|friends_timeline|unread_friends(?:_timeline|\/timeline)|unread_hot_timeline|container_timeline(?:_hot|_unread|_topic|_topicpage)?|repost_timeline)|guest\/container_timeline_hot|groups\/timeline|cardlist|container\/get_item)\/?$/ },
  { type: 'comments', key: 'COMMENTS', re: /^\/(?:comments\/(?:mix_comments|build_comments|hotflow)|statuses\/(?:container_detail_comment|container_detail_mix|container_detail_forward))\/?$/ },
  { type: 'detail', key: 'DETAIL', re: /^\/statuses\/(?:container_detail|extend|show)\/?$/ },
  { type: 'discovery', key: 'DISCOVERY', re: /^\/search\/(?:finder|container_timeline|container_discover)\/?$/ },
  { type: 'search', key: 'SEARCH', re: /^\/(?:searchall|flowpage|page)\/?$/ },
  { type: 'video', key: 'VIDEO', re: /^\/(?:video\/(?:flow_stream|flow_stream_cache|tiny_stream_video_list|community_tab|full_screen_stream)|statuses\/video_mixtimeline)\/?$/ },
  { type: 'profile', key: 'PROFILE', re: /^\/profile\/(?:me|container_timeline)\/?$/ },
  { type: 'messages', key: 'MESSAGES', re: /^\/messageflow\/?$/ }
];

// Deliberately redundant denylist: even if an allowlist is expanded later,
// publication and account operations remain untouched.
const PROTECTED_PATH = /\/(?:statuses\/(?:update|upload|send|create|edit|destroy|share|repost|comment|publish)|(?:compose|composer|publisher|publish|draft|drafts|upload|uploads|media\/upload|photo\/upload|login|logout|account|oauth|payment|pay|order|verify|verification))(?:\/|$)/i;
const LIST_KEYS = new Set([
  'items', 'statuses', 'datas', 'cards', 'card_group', 'comments',
  'comments_list', 'comment_list', 'commentList', 'list', 'resultList',
  'feeds', 'feed', 'sections', 'contents', 'mblog_list', 'status_list',
  'head_cards', 'top_cards', 'header_cards', 'channels', 'groups',
  'reposts', 'hot_reposts'
]);
const NEST_KEYS = new Set([
  'data', 'result', 'payload', 'status', 'mblog', 'card', 'pageHeader',
  'detailInfo', 'item', 'container', 'feed', 'comment', 'timeline', 'main',
  'head', 'body', 'tab', 'content', 'dataInfo', 'channelInfo',
  'payload', 'header', 'insert_data'
]);
const EXPLICIT_AD_TYPES = new Set([
  'ad', 'ads', 'advertisement', 'commercial', 'sponsored', 'sponsor',
  'feed_ad', 'native_ad', 'ad_card', 'promoted_ad', 'promoted_post'
]);

const obj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const flagged = v => v === true || v === 1 || v === '1' || v === 'true';
const adType = v => typeof v === 'string' && EXPLICIT_AD_TYPES.has(v.toLowerCase());
const adLabel = v => typeof v === 'string' && /^(?:广告|商业广告|广告微博|推广广告|广告推荐)$/u.test(v.trim());

function isClearlyAd(item) {
  if (!obj(item)) return false;
  // Only inspect the item and its immediate content wrappers. Never inspect
  // embedded user profiles or arbitrary descendants for ad-looking strings.
  for (const data of [item, item.data, item.status, item.mblog, item.card]) {
    if (!obj(data)) continue;
    for (const name of ['is_ad', 'is_ads', 'isAd', 'isAds', 'isAliMaMaAD']) {
      if (flagged(data[name])) return true;
    }
    if (data.ad_state === 1 || data.ad_state === '1') return true;
    if (adLabel(data.mblogtypename) || adLabel(data.adType) || adLabel(data.commentAdType)) return true;
    for (const name of ['category', 'model_type', 'card_type', 'cardType', 'bizType', 'ad_type']) {
      if (adType(data[name])) return true;
    }
    if (obj(data.promotion) && (adType(data.promotion.type) || flagged(data.promotion.is_ad))) return true;
    if (obj(data.ads_material_info) && (flagged(data.ads_material_info.is_ads) || flagged(data.ads_material_info.is_ad))) return true;
    if (adLabel(data.content_auth_info?.content_auth_title)) return true;
    // A known advertising position identifier; not a generic 'promote' string.
    if (typeof data.itemid === 'string' && /(?:^|[&_:])is_ad_pos(?:[&_:]|$)/i.test(data.itemid)) return true;
  }
  return false;
}

/**
 * Stronger only on feed-like listing responses, never on post contents.
 * promotion_info may identify a recommendation rather than a paid ad.
 */
function isStrongFeedAd(item) {
  if (!obj(item)) return false;
  const candidates = [
    item, item.data, item.status, item.mblog, item.card,
    item.data?.mblog, item.data?.status, item.data?.card,
    item.card?.mblog, item.card?.data, item.card?.data?.mblog
  ];
  for (const data of candidates) {
    if (!obj(data)) continue;
    if (data.promotion != null || data.promotion_info != null) return true;
    if (typeof data.mblogtypename === 'string' &&
        /(广告|热推)/u.test(data.mblogtypename)) return true;
    if (typeof data.content_auth_info?.content_auth_title === 'string' &&
        data.content_auth_info.content_auth_title.includes('广告')) return true;
    if (typeof data.itemid === 'string' && data.itemid.includes('is_ad_pos')) return true;
  }
  return false;
}

function readRoute(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch (_) { return null; }
  const host = url.hostname.toLowerCase();
  const path = url.pathname;
  // The ad module must never participate in publication or account endpoints.
  if (PROTECTED_PATH.test(path)) return null;
  if (host === 'bootpreload.uve.weibo.com' && /^\/v\d+\/ad\/preload\/?$/.test(path)) {
    return { type: 'splash', key: 'SPLASH', path, host };
  }
  if (host === 'bootrealtime.uve.weibo.com' && /^\/v\d+\/ad\/realtime\/?$/.test(path)) {
    return { type: 'splash', key: 'SPLASH', path, host };
  }
  if (host === 'sdkapp.uve.weibo.com' && /^\/interface\/sdk\/sdkad\.php\/?$/.test(path)) {
    return { type: 'splash', key: 'SPLASH', path, host };
  }
  if (host === 'wbapp.uve.weibo.com' && /^\/(?:wbapplua\/wbpullad\.lua|preload\/get_ad)\/?$/.test(path)) {
    return { type: 'splash', key: 'SPLASH', path, host };
  }
  if (!WEB_API_HOSTS.has(host) || !path.startsWith('/2/')) return null;
  const routePath = path.slice(2); // /2/statuses/... → /statuses/...
  const route = ROUTES.find(entry => entry.re.test(routePath));
  return route ? { type: route.type, key: route.key, path, host } : null;
}

function clearSplash(objValue) {
  if (!obj(objValue)) return 0;
  let changed = 0;
  const arrays = ['ads', 'ad', 'ad_list', 'ads_list', 'ads_groups', 'bidding_ads', 'splash_ads', 'feed_ad_arr'];
  for (const key of arrays) {
    if (Array.isArray(objValue[key]) && objValue[key].length > 0) {
      objValue[key] = [];
      changed++;
    }
  }
  if (obj(objValue.adMap) && Object.keys(objValue.adMap).length > 0) {
    objValue.adMap = {};
    changed++;
  }
  for (const key of ['cacheAdInfo', 'realTimeAd']) {
    if (Object.prototype.hasOwnProperty.call(objValue, key) && objValue[key] !== null) {
      objValue[key] = null;
      changed++;
    }
  }
  for (const key of ['show_push_splash_ad']) {
    if (objValue[key] === true) { objValue[key] = false; changed++; }
  }
  return changed;
}

function cleanSplash(root) {
  let changed = 0;
  // Only known, splash-specific containers: no arbitrary traversal.
  for (const part of [root, root.data, root.data?.data, root.cached_ad,
    root.data?.cached_ad, root.data?.splash, root.data?.splash_ad]) {
    changed += clearSplash(part);
  }
  return changed;
}

function cleanMessages(root) {
  // fmz200/zmqcherish: a specific ad marker on a message card.
  // Do not touch normal messages, chats, counts, account notifications or
  // generic 'recommended' messages; neither filter the entire messageflow.
  let removed = 0;
  for (const owner of [root, root?.data]) {
    if (!obj(owner) || !Array.isArray(owner.messages)) continue;
    const original = owner.messages.length;
    const kept = owner.messages.filter(message => {
      const tag = message?.msg_card?.ad_tag;
      // A nonempty ad_tag is a specific ad field, unlike vague names/text.
      return tag === undefined || tag === null || tag === false || tag === '' || tag === 0;
    });
    removed += original - kept.length;
    if (kept.length !== original) owner.messages = kept;
  }
  return removed;
}

function cleanFeed(root, mode) {
  const stats = { removed: 0, cleared: 0, visited: 0 };
  const removeAd = item => isClearlyAd(item) ||
    (STRONG_FEED_MODES.has(mode) && isStrongFeedAd(item));
  const walk = (node, depth) => {
    if (!obj(node) || depth > 7 || stats.visited > 9000) return;
    stats.visited++;
    for (const [key, val] of Object.entries(node)) {
      if (Array.isArray(val) && LIST_KEYS.has(key)) {
        // Only list items can be removed; never delete a normal user, thread or field.
        const next = [];
        for (const item of val) {
          if (removeAd(item)) { stats.removed++; continue; }
          if (obj(item)) walk(item, depth + 1);
          next.push(item);
        }
        if (next.length !== val.length) node[key] = next;
      } else if (obj(val) && NEST_KEYS.has(key)) {
        walk(val, depth + 1);
      } else if (Array.isArray(val) && key === 'data') {
        const next = [];
        for (const item of val) {
          if (removeAd(item)) { stats.removed++; continue; }
          if (obj(item)) walk(item, depth + 1);
          next.push(item);
        }
        if (next.length !== val.length) node[key] = next;
      }
    }
  };
  if (Array.isArray(root.data)) {
    const next = [];
    for (const item of root.data) {
      if (removeAd(item)) { stats.removed++; continue; }
      if (obj(item)) walk(item, 1);
      next.push(item);
    }
    if (next.length !== root.data.length) root.data = next;
  }
  walk(root, 0);
  // Only clear *explicitly named* ad collections in selected feed-like routes.
  // Do not touch 'trends', 'recommend', 'user', 'publisher_list' or anything else.
  if (['feed', 'discovery', 'search', 'video', 'profile', 'detail'].includes(mode)) {
    for (const node of [root, root.data]) {
      if (!obj(node)) continue;
      for (const key of ['ad', 'ads', 'ad_list', 'ads_list', 'advertises', 'advertisements', 'feed_ad_arr']) {
        if (Array.isArray(node[key]) && node[key].length > 0) {
          node[key] = [];
          stats.cleared++;
        }
      }
    }
  }
  return stats.removed + stats.cleared;
}

export default async function(ctx) {
  const rawUrl = ctx?.request?.url;
  if (typeof rawUrl !== 'string' || !ctx?.response) return;
  const route = readRoute(rawUrl);
  if (!route) return;
  // Permit POST listing responses on explicit feed-like routes; never publish paths.
  if (typeof ctx.request.method !== 'string') return;
  const method = ctx.request.method.toUpperCase();
  if (method !== 'GET' && !(method === 'POST' && STRONG_FEED_MODES.has(route.type))) return;
  if (typeof ctx.response.status === 'number' && (ctx.response.status < 200 || ctx.response.status >= 300)) return;
  // Fail closed to no modification; this never modifies requests.
  let raw;
  try { raw = await ctx.response.text(); } catch (_) { return; }
  if (typeof raw !== 'string' || !raw.trim()) return { body: raw ?? '' };
  try {
    // sdkad.php has historically returned JSON + trailing OK.
    const suffix = route.path.endsWith('sdkad.php') && /}\s*OK\s*$/.test(raw) ? 'OK' : '';
    const jsonText = suffix ? raw.slice(0, raw.lastIndexOf('OK')).trimEnd() : raw;
    const root = JSON.parse(jsonText);
    if (!obj(root) || root.ok === 0 || root.success === false || root.error) return { body: raw };
    const changes = route.type === 'splash' ? cleanSplash(root) :
      route.type === 'messages' ? cleanMessages(root) : cleanFeed(root, route.type);
    if (!changes) return { body: raw };
    return { body: JSON.stringify(root) + suffix };
  } catch (_) {
    // Never produce '{}' on failure, never mask an upstream error.
    return { body: raw };
  }
}
