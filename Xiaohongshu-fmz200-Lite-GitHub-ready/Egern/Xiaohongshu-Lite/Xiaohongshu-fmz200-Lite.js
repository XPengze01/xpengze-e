/**
 * 小红书 fmz200 精简改写版（Egern JS API）
 * 基于 fmz200/wool_scripts 的公开接口及处理逻辑重新整理。
 * 仅处理开屏、明确标记的广告、图片/视频去水印与保存。
 * 不修改搜索、购物、直播、画质或正常评论的内容。
 */
export default async function (ctx) {
  if (!ctx?.request?.url || !ctx?.response) return;
  const url = ctx.request.url;
  let raw;
  try { raw = await ctx.response.text(); } catch (_) { return; }
  if (!raw) return { body: raw };
  let root;
  try { root = JSON.parse(raw); } catch (_) { return { body: raw }; }
  let edited = false;

  const isAd = (entry) => {
    if (!entry || typeof entry !== 'object') return false;
    if (entry.is_ad === true || entry.is_ads === true) return true;
    const info = entry.ads_info;
    return info != null && (typeof info !== 'object' || Object.keys(info).length > 0);
  };
  const removeMarkedAds = (items) => {
    if (!Array.isArray(items)) return items;
    const clean = items.filter(item => !isAd(item));
    if (clean.length !== items.length) edited = true;
    return clean;
  };
  const allowSave = (note) => {
    if (!note || typeof note !== 'object') return;
    if (note.media_save_config && typeof note.media_save_config === 'object') {
      note.media_save_config.disable_save = false;
      note.media_save_config.disable_watermark = true;
      note.media_save_config.disable_weibo_cover = true;
      edited = true;
    }
    if (Array.isArray(note.function_switch)) {
      for (const sw of note.function_switch) {
        if (sw?.type === 'image_download' || sw?.type === 'video_download') {
          if (sw.enable !== true) { sw.enable = true; edited = true; }
        }
      }
    }
    // 仅在有功能入口列表时补充视频保存入口；不改变其他分享功能。
    if (Array.isArray(note.share_info?.function_entries) &&
        !note.share_info.function_entries.some(x => x?.type === 'video_download')) {
      note.share_info.function_entries.push({ type: 'video_download' });
      edited = true;
    }
  };
  const bestStream = (media) => {
    const s = media?.stream || media?.media?.stream;
    for (const arr of [s?.h265, s?.h264]) {
      if (Array.isArray(arr)) {
        const v = arr.find(x => typeof x?.master_url === 'string' && x.master_url);
        if (v) return v.master_url;
      }
    }
    return null;
  };
  const saveJSON = (key, value) => {
    try { ctx.storage.set(key, JSON.stringify(value)); } catch (_) {}
  };
  const loadJSON = (key) => {
    try { return JSON.parse(ctx.storage.get(key) || 'null'); } catch (_) { return null; }
  };

  try {
    // 1. 开屏广告：沿用 fmz200 的时间失效处理，而非删除整个配置。
    if (url.includes('/system_service/splash_config') && Array.isArray(root.data?.ads_groups)) {
      for (const group of root.data.ads_groups) {
        group.start_time = 3818332800;
        group.end_time = 3818419199;
        for (const ad of Array.isArray(group.ads) ? group.ads : []) {
          ad.start_time = 3818332800;
          ad.end_time = 3818419199;
        }
      }
      edited = true;
    }

    // 2. 首页信息流：只移除明确带广告标记的卡片，直播/商品/普通笔记保留。
    if (/\/v\d+\/(homefeed|followfeed)\?/.test(url)) {
      if (Array.isArray(root.data)) root.data = removeMarkedAds(root.data);
      else if (Array.isArray(root.data?.items)) root.data.items = removeMarkedAds(root.data.items);
    }

    // 3. 图片笔记与视频笔记：保留下载、去水印，不做画质增强。
    if (/\/note\/(imagefeed|feed|videofeed)\?/.test(url)) {
      const entries = Array.isArray(root.data) ? root.data : [root.data];
      for (const entry of entries) {
        if (Array.isArray(entry?.note_list)) {
          for (const note of entry.note_list) allowSave(note);
        } else {
          allowSave(entry);
        }
      }

      // 普通视频保存：缓存已经随笔记响应返回的直链，仅用于对应视频的保存请求。
      if (/\/note\/videofeed\?/.test(url)) {
        const videoURLs = {};
        for (const note of entries) {
          if (note?.id) {
            const stream = bestStream(note.video_info_v2);
            if (stream) videoURLs[note.id] = stream;
          }
        }
        if (Object.keys(videoURLs).length) saveJSON('xhs_lite_video_urls', videoURLs);
      }

      // Live Photo 保存：只缓存本次笔记中可验证的 file_id -> 视频链接。
      const liveURLs = {};
      for (const entry of entries) {
        const notes = Array.isArray(entry?.note_list) ? entry.note_list : [entry];
        for (const note of notes) {
          for (const img of Array.isArray(note?.images_list) ? note.images_list : []) {
            const stream = bestStream(img?.live_photo);
            if (img?.live_photo_file_id && stream) liveURLs[img.live_photo_file_id] = stream;
          }
        }
      }
      if (Object.keys(liveURLs).length) saveJSON('xhs_lite_live_urls', liveURLs);
    }

    // 4. 视频/Live Photo 保存：仅在存在匹配缓存时替换下载地址。
    if (/\/note\/video\/save\?/.test(url) && root.data?.note_id) {
      const stream = loadJSON('xhs_lite_video_urls')?.[root.data.note_id];
      if (stream) {
        root.data.download_url = stream;
        if (root.data.disable === true) {
          delete root.data.disable;
          delete root.data.msg;
          root.data.status = 2;
        }
        edited = true;
      }
    }
    if (url.includes('/note/live_photo/save') && Array.isArray(root.data?.datas)) {
      const urls = loadJSON('xhs_lite_live_urls') || {};
      for (const item of root.data.datas) {
        if (urls[item?.file_id]) { item.url = urls[item.file_id]; edited = true; }
      }
    }

    // 5. 评论区：仅去除明确标记的广告，保留正常评论、回复和分页结构。
    if (/\/note\/comment\/(list|sub_comments)\?/.test(url)) {
      if (Array.isArray(root.data?.comments)) {
        root.data.comments = removeMarkedAds(root.data.comments);
        for (const comment of root.data.comments) {
          if (Array.isArray(comment?.sub_comments)) {
            comment.sub_comments = removeMarkedAds(comment.sub_comments);
          }
        }
      }
      // 评论中的 Live Photo / 视频缓存，只用于评论视频下载接口。
      const commentURLs = {};
      for (const comment of Array.isArray(root.data?.comments) ? root.data.comments : []) {
        const all = [comment, ...(Array.isArray(comment.sub_comments) ? comment.sub_comments : [])];
        for (const c of all) {
          for (const pic of Array.isArray(c?.pictures) ? c.pictures : []) {
            if (!pic?.video_id || !pic?.video_info) continue;
            try {
              const stream = bestStream(JSON.parse(pic.video_info));
              if (stream) commentURLs[pic.video_id] = stream;
            } catch (_) {}
          }
          for (const video of Array.isArray(c?.videos) ? c.videos : []) {
            if (!video?.video_id || !video?.video_info) continue;
            try {
              const stream = bestStream(JSON.parse(video.video_info));
              if (stream) commentURLs[video.video_id] = stream;
            } catch (_) {}
          }
        }
      }
      if (Object.keys(commentURLs).length) saveJSON('xhs_lite_comment_urls', commentURLs);
    }
    if (url.includes('/interaction/comment/video/download') && root.data?.video?.video_id) {
      const stream = loadJSON('xhs_lite_comment_urls')?.[root.data.video.video_id];
      if (stream) { root.data.video.video_url = stream; edited = true; }
    }

    return { body: edited ? JSON.stringify(root) : raw };
  } catch (_) {
    // 处理出现不兼容时，优先保证应用正常响应。
    return { body: raw };
  }
};
