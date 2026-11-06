/**
 * 闲鱼开屏广告处理：Egern 原生 HTTP response 脚本
 * 只处理 splash.ads / splash.async.ads，不修改首页、订单、支付或 HTTPDNS。
 * 对非成功响应、无法解析的 JSON 和未知数据结构直接透传。
 */
export default async function (ctx) {
  const url = ctx?.request?.url || "";
  if (!/\/mtop\.taobao\.idlecommerce\.splash\.(?:async\.)?ads(?:\/|\?|$)/i.test(url)) return;
  if (!ctx?.response) return;
  if (typeof ctx.response.status === "number" && ctx.response.status !== 200) return;

  let raw;
  try { raw = await ctx.response.text(); } catch (_) { return; }
  if (typeof raw !== "string" || !raw) return;

  let root;
  try { root = JSON.parse(raw); } catch (_) { return; }
  if (!root || typeof root !== "object" || Array.isArray(root)) return;
  if (root.success === false) return;
  if (Array.isArray(root.ret) && root.ret.some(x => typeof x === "string" && !x.startsWith("SUCCESS::"))) return;

  const data = root.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) return;

  let changed = false;
  if (!data.adMap || typeof data.adMap !== "object" || Array.isArray(data.adMap) ||
      Object.keys(data.adMap).length > 0) {
    data.adMap = {};
    changed = true;
  }
  for (const key of ["cacheAdInfo", "realTimeAd"]) {
    if (Object.prototype.hasOwnProperty.call(data, key) && data[key] !== null) {
      data[key] = null;
      changed = true;
    }
  }

  if (!changed) return;
  return { body: JSON.stringify(root) };
}
