/**
 * 小红书 / RedNote Lite V2 — Egern 原生响应脚本
 * 目标：开屏、明确标记的首页/视频/评论广告、图片及视频去水印/保存。
 * 不处理搜索、商品/直播、音乐、地点、个人页、聊天和普通推荐。
 * 参考：fmz200/wool_scripts、patrickyanxxxxx/rednote-egern（功能思路）
 * 更新须人工确认；出现异常时保留原始响应，避免影响浏览。
 */
const VERSION = '2.0.0';
const VIDEO_KEY = 'xhs_lite_v2_video_urls';
const LIVE_KEY = 'xhs_lite_v2_live_urls';
const COMMENT_KEY = 'xhs_lite_v2_comment_urls';
const AD_MODELS = new Set([
  'ad', 'ads', 'advertisement', 'commercial', 'sponsor', 'sponsored',
  'promoted_note', 'brand_ad', 'feed_ad', 'native_ad'
]);

function obj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function flag(v) { return v === true || v === 1 || v === '1' || v === 'true'; }
function own(o, key) { return Object.prototype.hasOwnProperty.call(o, key); }
function isAd(item) {
  if (!obj(item)) return false;
  for (const key of ['is_ad', 'is_ads', 'is_sponsored', 'sponsored', 'promoted']) {
    if (flag(item[key])) return true;
  }
  // 广告专用描述块存在即视为广告；空对象也是已知广告返回形式。
  for (const key of ['ads_info', 'ad_info', 'advertisement_info']) {
    if (own(item, key) && item[key] !== null && item[key] !== false) return true;
  }
  for (const key of ['model_type', 'card_type', 'item_type', 'display_type']) {
    const v = item[key];
    if (typeof v === 'string' && AD_MODELS.has(v.toLowerCase())) return true;
  }
  const reason = item.recommend_reason || item.recommend_type;
  return typeof reason === 'string' && /(?:^|[_-])(?:ad|ads|sponsor|sponsored|commercial)(?:[_-]|$)/i.test(reason);
}

function filterAds(items) {
  if (!Array.isArray(items)) return false;
  const original = items.length;
  for (let i = items.length - 1; i >= 0; i--) {
    if (isAd(items[i])) items.splice(i, 1);
  }
  return items.length !== original;
}
function filterKnownLists(data) {
  if (Array.isArray(data)) return filterAds(data);
  if (!obj(data)) return false;
  let changed = false;
  for (const key of ['items', 'notes', 'cards']) {
    if (Array.isArray(data[key])) changed = filterAds(data[key]) || changed;
  }
  return changed;
}
function filterComments(data) {
  if (!obj(data) || !Array.isArray(data.comments)) return false;
  let changed = filterAds(data.comments);
  for (const comment of data.comments) {
    if (obj(comment) && Array.isArray(comment.sub_comments)) {
      changed = filterAds(comment.sub_comments) || changed;
    }
  }
  return changed;
}

function enableSave(note) {
  if (!obj(note)) return false;
  let changed = false;
  const settings = note.media_save_config;
  if (obj(settings)) {
    const values = {
      disable_save: false,
      disable_watermark: true,
      disable_weibo_cover: true
    };
    for (const [key, value] of Object.entries(values)) {
      if (settings[key] !== value) { settings[key] = value; changed = true; }
    }
  }
  if (Array.isArray(note.function_switch)) {
    for (const entry of note.function_switch) {
      if (obj(entry) && (entry.type === 'image_download' || entry.type === 'video_download')) {
        if (entry.enable !== true) { entry.enable = true; changed = true; }
        if (own(entry, 'reason')) { delete entry.reason; changed = true; }
      }
    }
  }
  // 仅在确实有视频的笔记里补视频保存入口；不改图片笔记的分享菜单。
  const videoNote = obj(note.video_info_v2) || obj(note.video_info) ||
    note.type === 'video' || note.note_type === 'video';
  const entries = note.share_info?.function_entries;
  if (videoNote && Array.isArray(entries) &&
      !entries.some(e => obj(e) && e.type === 'video_download')) {
    entries.push({ type: 'video_download' });
    changed = true;
  }
  return changed;
}

function collectNotes(data) {
  const notes = [];
  const add = (v) => {
    if (!obj(v)) return;
    if (Array.isArray(v.note_list)) {
      for (const note of v.note_list) add(note);
    } else if (obj(v.note)) {
      add(v.note);
    } else if (Array.isArray(v.items)) {
      for (const note of v.items) add(note);
    } else {
      notes.push(v);
    }
  };
  if (Array.isArray(data)) for (const v of data) add(v);
  else add(data);
  return notes;
}

function bestStream(media) {
  if (!obj(media)) return null;
  const s = media.stream || media.media?.stream;
  // 只读取服务端已提供的视频地址，不修改播放清晰度或编码。
  for (const arr of [s?.h265, s?.h264]) {
    if (!Array.isArray(arr)) continue;
    for (const variant of arr) {
      if (typeof variant?.master_url === 'string' && /^https?:\/\//.test(variant.master_url)) {
        return variant.master_url;
      }
    }
  }
  return null;
}
function readJSON(ctx, key) {
  try {
    if (typeof ctx.storage?.getJSON === 'function') return ctx.storage.getJSON(key) || {};
    return JSON.parse(ctx.storage?.get(key) || '{}');
  } catch (_) { return {}; }
}
function mergeCache(ctx, key, additions) {
  if (!obj(additions) || !Object.keys(additions).length) return;
  try {
    const combined = { ...readJSON(ctx, key), ...additions };
    const recent = Object.entries(combined).slice(-100);
    const out = Object.fromEntries(recent);
    if (typeof ctx.storage?.setJSON === 'function') ctx.storage.setJSON(key, out);
    else ctx.storage?.set(key, JSON.stringify(out));
  } catch (_) { /* 本地存储失败不影响阅读 */ }
}

function cleanSplash(root, path) {
  const data = root.data;
  if (!obj(data)) return false;
  let changed = false;
  if (path.endsWith('/splash_config')) {
    for (const key of ['ads_groups', 'bidding_ads', 'splash_ads']) {
      if (Array.isArray(data[key]) && data[key].length) { data[key] = []; changed = true; }
    }
    if (own(data, 'per_day_max_show') && data.per_day_max_show !== 0) {
      data.per_day_max_show = 0; changed = true;
    }
  } else {
    // 只改已知的开屏广告/跟踪字段，不生成虚假的整体响应结构。
    for (const key of ['ads_groups', 'bidding_ads', 'ads', 'dspList']) {
      if (Array.isArray(data[key]) && data[key].length) { data[key] = []; changed = true; }
    }
    for (const key of ['track_url', 'track_id', 'request_id']) {
      if (own(data, key) && data[key] !== '') { data[key] = ''; changed = true; }
    }
    if (own(data, 'ads_id') && data.ads_id !== '-1') { data.ads_id = '-1'; changed = true; }
  }
  return changed;
}

function extractDownloadCaches(notes) {
  const videos = {}, lives = {};
  for (const note of notes) {
    const id = note.id || note.note_id;
    const url = bestStream(note.video_info_v2) || bestStream(note.video_info);
    if (id && url) videos[String(id)] = url;
    const images = Array.isArray(note.images_list) ? note.images_list :
      Array.isArray(note.image_list) ? note.image_list : [];
    for (const picture of images) {
      const fileId = picture?.live_photo_file_id || picture?.live_photo?.file_id;
      const liveUrl = bestStream(picture?.live_photo);
      if (fileId && liveUrl) lives[String(fileId)] = liveUrl;
    }
  }
  return { videos, lives };
}
function extractCommentVideos(data) {
  const cache = {};
  const comments = Array.isArray(data?.comments) ? data.comments : [];
  for (const comment of comments) {
    const nested = [comment, ...(Array.isArray(comment?.sub_comments) ? comment.sub_comments : [])];
    for (const entry of nested) {
      for (const prop of ['pictures', 'videos']) {
        const parts = Array.isArray(entry?.[prop]) ? entry[prop] : [];
        for (const media of parts) {
          const id = media?.video_id;
          let info = media?.video_info;
          if (typeof info === 'string') {
            try { info = JSON.parse(info); } catch (_) { info = null; }
          }
          const url = bestStream(info);
          if (id && url) cache[String(id)] = url;
        }
      }
    }
  }
  return cache;
}

export default async function(ctx) {
  if (!ctx?.request?.url || !ctx.response) return;
  let raw;
  try { raw = await ctx.response.text(); }
  catch (_) { return; }
  if (!raw) return { body: raw };

  let root, path;
  try {
    root = JSON.parse(raw);
    path = new URL(ctx.request.url).pathname;
  } catch (_) { return { body: raw }; }
  if (!obj(root)) return { body: raw };
  // 不改服务器明确返回错误的响应。
  if (root.success === false || (typeof root.code === 'number' && root.code !== 0)) {
    return { body: raw };
  }
  let changed = false;
  try {
    if (/\/system_service\/(?:splash_config|splash_async_optimization|splash_online_decision)\/?$/.test(path)) {
      changed = cleanSplash(root, path);
    } else if (/\/v\d+\/(?:homefeed|followfeed)\/?$/.test(path)) {
      changed = filterKnownLists(root.data);
    } else if (/\/v\d+\/note\/(?:imagefeed|feed|videofeed|detailfeed(?:\/preload)?)\/?$/.test(path)) {
      // 视频流也需要过滤明确标记的广告，其余商品/直播正常保留。
      if (/\/note\/videofeed\/?$/.test(path)) changed = filterKnownLists(root.data);
      const notes = collectNotes(root.data);
      for (const note of notes) changed = enableSave(note) || changed;
      const caches = extractDownloadCaches(notes);
      mergeCache(ctx, VIDEO_KEY, caches.videos);
      mergeCache(ctx, LIVE_KEY, caches.lives);
    } else if (/\/v\d+\/note\/comment\/(?:list|sub_comments)\/?$/.test(path)) {
      changed = filterComments(root.data);
      mergeCache(ctx, COMMENT_KEY, extractCommentVideos(root.data));
    } else if (/\/v\d+\/note\/video\/save\/?$/.test(path)) {
      const id = root.data?.note_id;
      const url = id && readJSON(ctx, VIDEO_KEY)[String(id)];
      if (url && obj(root.data)) {
        if (root.data.download_url !== url) { root.data.download_url = url; changed = true; }
        if (root.data.disable === true) {
          delete root.data.disable;
          delete root.data.msg;
          root.data.status = 2;
          changed = true;
        }
      }
    } else if (/\/v\d+\/note\/live_photo\/save\/?$/.test(path)) {
      const cache = readJSON(ctx, LIVE_KEY);
      if (Array.isArray(root.data?.datas)) {
        for (const media of root.data.datas) {
          const url = cache[String(media?.file_id)];
          if (url && media.url !== url) { media.url = url; changed = true; }
        }
      }
    } else if (/\/v1\/interaction\/comment\/video\/download\/?$/.test(path)) {
      const id = root.data?.video?.video_id;
      const url = id && readJSON(ctx, COMMENT_KEY)[String(id)];
      if (url && root.data.video.video_url !== url) {
        root.data.video.video_url = url;
        changed = true;
      }
    }
    return { body: changed ? JSON.stringify(root) : raw };
  } catch (_) {
    return { body: raw };
  }
}
