/* 中国电信 Hark iOS 界面适配版。
 * 后端：IBL3ND/module；界面：zhaohantao1360-hash/Hark。
 * 不包含移动的登录抓取、后台保活或报告接口。 */
/*
 * 中国电信小组件（Egern 版，App RSA 登录）
 * 移植自 Scriptable「中国电信」3.0.0-rsa（2Ya&脑瓜，RSA 登录 + 电信官方 API）
 * 登录方式：App 官方接口 userLoginNormal（RSA 加密）+ qryImportantData 查数
 * 账号存在模块设置里，token 失效时自动重登。
 * 30 分钟缓存：30 分钟内直接用缓存，不调接口，减少登录次数。
 *
 * 环境变量（在模块 compat_arguments / generic env 里填）：
 *   CT_PHONE              手机号（必填）
 *   CT_PASSWORD           服务密码 6 位数字（必填，与 CT_SERVICE_PASSWORD 二选一）
 *   CT_SERVICE_PASSWORD   服务密码（CT_PASSWORD 的别名，填一个即可）
 *   CT_DEVICE_ID          设备 ID（可选）：在作者网页短信登录授权后复制
 *                         不填则用随机设备 ID，可能需要多试几次才登上
 *   CT_SHOW_USED_FLOW     'true' 显示已用流量，否则显示剩余流量
 *   CT_SHOW_USED_VOICE    'true' 显示已用语音，否则显示剩余语音
 *   CT_SHOW_GENERAL_FLOW  'false' 不统计通用流量，默认显示
 *   CT_SHOW_DIRECTIONAL_FLOW 'false' 不统计定向流量，默认显示
 *   CT_TITLE              小组件标题，默认 "中国电信"
 *
 * 数据来源：https://appgologin.189.cn:9031/login/client/userLoginNormal
 *           https://appfuwu.189.cn:9021/query/qryImportantData
 * 注意：密码只存在你自己的 Egern 模块设置里，不发给任何第三方。
 */

const URLS = {
  login: 'https://appgologin.189.cn:9031/login/client/userLoginNormal',
  query: 'https://appfuwu.189.cn:9021/query/qryImportantData',
};

const FLOW_COLOR = '#FF6620';
const VOICE_COLOR = '#78C100';

const COLORS = {
  bg: {
    light: '#FFFFFF',
    dark: '#2C2C2E',
  },
  border: {
    light: '#E5E5EA',
    dark: '#3A3A3C',
  },
  title: {
    light: '#666666',
    dark: '#8E8E93',
  },
  value: {
    light: '#1C1C1E',
    dark: '#FFFFFF',
  },
  time: {
    light: '#999999',
    dark: '#666666',
  },
  error: {
    light: '#FF3B30',
    dark: '#FF453A',
  },
  capsuleBg: {
    light: '#FFFFFF15',
    dark: '#FFFFFF10',
  },
  accent: {
    light: '#FF6620',
    dark: '#FF854D',
  },
};

function formatFlow(flow) {
  const remain = flow / 1024;
  if (remain < 1024) {
    return { amount: remain.toFixed(2), unit: 'MB' };
  }
  return { amount: (remain / 1024).toFixed(2), unit: 'GB' };
}

function pad2(n) {
  return n < 10 ? `0${n}` : `${n}`;
}

function fmtTime(ts) {
  const d = new Date(ts);
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

function _safeN(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function transNumber(str, encode = true) {
  return [...String(str || '')].map((c) => String.fromCharCode((c.charCodeAt(0) + (encode ? 2 : -2)) & 0xffff)).join('');
}

function getBeijingTimestamp() {
  const bjDate = new Date(Date.now() + 8 * 3600 * 1000);
  const yyyy = String(bjDate.getFullYear());
  const MM = String(bjDate.getMonth() + 1).padStart(2, '0');
  const dd = String(bjDate.getDate()).padStart(2, '0');
  const HH = String(bjDate.getHours()).padStart(2, '0');
  const mm = String(bjDate.getMinutes()).padStart(2, '0');
  const ss = String(bjDate.getSeconds()).padStart(2, '0');
  return `${yyyy}${MM}${dd}${HH}${mm}${ss}`;
}

const RSA_MOD_HEX = 'c190b4f5e53855833ebf34e97ab3c18d3e87dd5b359b0a45a791a026eced8b8e43351fb74cbf3922a9dc54d368da9864472d7fd934c0971e73dc5bfb0386214204dd7ca85bf2f20e9561bf50b6ba08d3d7b5efab3e642b62bfb85b8a7d9c0938fdf625299c4968666d7d9701f2a3af6ee543223cca6ad3f5ca04ef2562137f83';

function _modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function _base64Encode(bytes) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += chars[b0 >> 2];
    out += chars[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? chars[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? chars[b2 & 63] : '=';
  }
  return out;
}

function rsaEncrypt(text) {
  const data = [...String(text)].map((c) => c.charCodeAt(0) & 0xff);
  const k = 128;
  if (data.length > k - 11) throw new Error('RSA 明文过长');
  const psLen = k - data.length - 3;
  const ps = [];
  while (ps.length < psLen) {
    const r = Math.floor(Math.random() * 255) + 1;
    if (r !== 0) ps.push(r);
  }
  const em = [0x00, 0x02, ...ps, 0x00, ...data];
  let hex = '';
  for (const b of em) hex += b.toString(16).padStart(2, '0');
  const m = BigInt('0x' + RSA_MOD_HEX);
  const c = _modPow(BigInt('0x' + hex), 65537n, m);
  let cHex = c.toString(16).padStart(256, '0');
  const out = [];
  for (let i = 0; i < cHex.length; i += 2) out.push(parseInt(cHex.slice(i, i + 2), 16));
  return _base64Encode(out);
}

async function _postJson(ctx, url, bodyObj) {
  let resp;
  try {
    resp = await ctx.http.post(url, {
      headers: { 'Content-Type': 'application/json; charset=UTF-8' },
      body: JSON.stringify(bodyObj),
      timeout: 15000,
    });
  } catch (e) {
    const err = new Error(`network: ${url}`);
    err.transient = true;
    throw err;
  }
  if (!resp || resp.status !== 200) {
    const err = new Error(`HTTP ${resp ? resp.status : 'no-response'}: ${url}`);
    err.transient = true;
    throw err;
  }
  try {
    return await resp.json();
  } catch (e) {
    const err = new Error(`not-json: ${url}`);
    err.transient = true;
    throw err;
  }
}

function _getAccount(ctx) {
  const env = ctx.env || {};
  const phone = String(env.CT_PHONE || '').trim();
  const password = String(env.CT_PASSWORD || env.CT_SERVICE_PASSWORD || '').trim();
  const deviceId = String(env.CT_DEVICE_ID || '').trim();
  return { phone, password, deviceId };
}

async function telecomLogin(ctx, account) {
  const { phone, password, deviceId } = account;
  const uuid = String(Math.floor(Math.random() * 9e15 + 1e15));
  const ts = getBeijingTimestamp();
  const encryptText = `iPhone 14 15.4.0${deviceId || uuid.slice(0, 12)}${phone}${ts}${password}0$$$0.`;
  const encrypted = rsaEncrypt(encryptText);
  const loginBody = {
    content: {
      fieldData: {
        loginType: '4',
        accountType: '',
        isChinatelecom: '',
        systemVersion: '15.4.0',
        deviceUid: uuid.slice(0, 16),
        phoneNum: transNumber(phone),
        authentication: transNumber(password),
        androidId: deviceId ? transNumber(deviceId) : '',
        loginAuthCipherAsymmertric: encrypted,
      },
      attach: 'iPhone',
    },
    headerInfos: {
      code: 'userLoginNormal',
      clientType: '#12.2.0#channel50#iPhone 14 Pro#',
      timestamp: ts,
      shopId: '20002',
      source: '110003',
      sourcePassword: 'Sid98s',
      userLoginName: transNumber(phone),
    },
  };
  const loginData = await _postJson(ctx, URLS.login, loginBody);
  const rd = loginData && loginData.responseData;
  if (!rd || rd.resultCode !== '0000') {
    const err = new Error(`登录失败 ${rd ? rd.resultCode : 'no-response'}：${(rd && rd.resultDesc) || '未知错误'}`);
    err.resultCode = rd ? rd.resultCode : '';
    err.resultDesc = rd ? rd.resultDesc : '';
    throw err;
  }
  const { token, cityCode, provinceCode } = rd.data.loginSuccessResult || {};
  if (!token) throw new Error('登录成功但未返回 token');
  try {
    ctx.storage.set('ct_app_token', token);
    ctx.storage.set('ct_app_city', String(cityCode || ''));
    ctx.storage.set('ct_app_province', String(provinceCode || ''));
    ctx.storage.set('ct_app_token_ts', String(Date.now()));
  } catch (_) {}
  return { token, cityCode, provinceCode };
}

async function fetchImportantData(ctx, account, token, cityCode, provinceCode) {
  const ts = getBeijingTimestamp();
  const dataBody = {
    content: {
      fieldData: {
        provinceCode,
        cityCode,
        shopId: '20002',
        isChinatelecom: '0',
        account: transNumber(account.phone),
      },
      attach: 'test',
    },
    headerInfos: {
      code: 'qryImportantData',
      clientType: '#12.2.0#channel50#iPhone 14 Pro#',
      timestamp: ts,
      shopId: '20002',
      source: '110003',
      sourcePassword: 'Sid98s',
      userLoginName: transNumber(account.phone),
      token,
    },
  };
  const dataResp = await _postJson(ctx, URLS.query, dataBody);
  if (!dataResp || !dataResp.responseData) {
    const err = new Error(`查数失败：${(dataResp && dataResp.headerInfos && dataResp.headerInfos.reason) || 'Token 失效'}`);
    err.authFailed = true;
    throw err;
  }
  return dataResp.responseData.data;
}

function parseImportantData(apiData, opts) {
  const { showUsedFlow, showGeneralFlow, showDirectionalFlow } = opts;
  const balance = _safeN(apiData && apiData.balanceInfo && apiData.balanceInfo.indexBalanceDataInfo && apiData.balanceInfo.indexBalanceDataInfo.balance);
  const feeBalance = balance !== 0 ? balance : _safeN(apiData && apiData.balance);
  const fee = { title: '剩余话费', number: feeBalance.toFixed(2), unit: '元' };

  const common = (apiData && apiData.flowInfo && apiData.flowInfo.commonFlow) || {};
  const total = (apiData && apiData.flowInfo && apiData.flowInfo.totalAmount) || {};
  const gUsed = _safeN(common.used), gBalance = _safeN(common.balance), gTotal = _safeN(common.total);
  const tUsed = _safeN(total.used !== undefined ? total.used : apiData.usedFlux), tBalance = _safeN(total.balance), tTotal = _safeN(total.total !== undefined ? total.total : (tUsed + tBalance));
  const hasCommon = common.used !== undefined || common.balance !== undefined || common.total !== undefined;
  let used, balanceFlow, totalFlow;
  if (!hasCommon) {
    used = tUsed; balanceFlow = tBalance; totalFlow = tTotal;
  } else if (showGeneralFlow && showDirectionalFlow) {
    used = tUsed; balanceFlow = tBalance; totalFlow = tTotal;
  } else if (showGeneralFlow && !showDirectionalFlow) {
    used = gUsed; balanceFlow = gBalance; totalFlow = gTotal;
  } else if (!showGeneralFlow && showDirectionalFlow) {
    used = Math.max(0, tUsed - gUsed); balanceFlow = Math.max(0, tBalance - gBalance); totalFlow = Math.max(0, tTotal - gTotal);
  } else {
    used = tUsed; balanceFlow = tBalance; totalFlow = tTotal;
  }
  const balanceFmt = formatFlow(balanceFlow);
  const usedFmt = formatFlow(used);
  const flow = {
    title: '剩余流量',
    number: balanceFmt.amount,
    unit: balanceFmt.unit,
    percent: +(totalFlow > 0 ? ((balanceFlow / totalFlow) * 100).toFixed(2) : '0'),
    color: FLOW_COLOR,
  };
  if (showUsedFlow) {
    flow.title = '已用流量';
    flow.number = usedFmt.amount;
    flow.unit = usedFmt.unit;
  }

  const voiceInfo = (apiData && apiData.voiceInfo && apiData.voiceInfo.voiceDataInfo) || {};
  const vTotal = _safeN(voiceInfo.total !== undefined ? voiceInfo.total : apiData.totalVoice);
  const vUsed = _safeN(voiceInfo.used !== undefined ? voiceInfo.used : apiData.usedVoice);
  const vBalance = _safeN(voiceInfo.balance !== undefined ? voiceInfo.balance : (vTotal - vUsed));
  const showUsedVoice = opts.showUsedVoice;
  const voice = {
    title: showUsedVoice ? '已用语音' : '剩余语音',
    number: `${showUsedVoice ? vUsed : vBalance}`,
    unit: '分钟',
    percent: +(vTotal > 0 ? (((showUsedVoice ? vUsed : vBalance) / vTotal) * 100).toFixed(2) : '0'),
    color: VOICE_COLOR,
  };

  return { fee, flow, voice, updatedAt: Date.now() };
}

function _notifyAuthFailedOnce(ctx, account, err) {
  try {
    const marker = `${account.phone.slice(-4)}:${err && err.resultCode ? err.resultCode : (err && err.message) || ''}`;
    if (ctx.storage.get('ct_auth_notified') === marker) return;
    ctx.storage.set('ct_auth_notified', marker);
    ctx.notify({ title: '中国电信', body: `登录失败：${(err && err.message) || '请检查手机号/服务密码/设备ID'}` });
  } catch (_) {}
}

function _clearAuthFlag(ctx) {
  try { ctx.storage.delete('ct_auth_notified'); } catch (_) {}
}

async function loadData(ctx) {
  const settings = {
    showUsedFlow: ctx.env.CT_SHOW_USED_FLOW === 'true',
    showUsedVoice: ctx.env.CT_SHOW_USED_VOICE === 'true',
    showGeneralFlow: ctx.env.CT_SHOW_GENERAL_FLOW !== 'false',
    showDirectionalFlow: ctx.env.CT_SHOW_DIRECTIONAL_FLOW !== 'false',
  };
  const account = _getAccount(ctx);
  const configured = !!(account.phone && account.password);
  if (!configured) {
    return { configured: false, ds: null, fromCache: false, authFailed: false, authError: '' };
  }

  try {
    const rawCache = ctx.storage.getJSON('ct_raw');
    const dsCache = ctx.storage.getJSON('ct_datasource');
    const at = (rawCache && rawCache.at) || (dsCache && dsCache.updatedAt) || 0;
    if (at && Date.now() - at < 30 * 60 * 1000) {
      if (rawCache && rawCache.apiData) {
        const ds = parseImportantData(rawCache.apiData, settings);
        ds.updatedAt = at;
        return { configured, ds, fromCache: false, authFailed: false, authError: '' };
      }
      if (dsCache) {
        return { configured, ds: dsCache, fromCache: false, authFailed: false, authError: '' };
      }
    }
  } catch (_) {}

  let token = '';
  let cityCode = '';
  let provinceCode = '';
  try {
    token = ctx.storage.get('ct_app_token') || '';
    cityCode = ctx.storage.get('ct_app_city') || '';
    provinceCode = ctx.storage.get('ct_app_province') || '';
  } catch (_) {}

  const _tryFetch = async (tok, city, prov) => {
    const apiData = await fetchImportantData(ctx, account, tok, city, prov);
    const ds = parseImportantData(apiData, settings);
    try {
      ctx.storage.setJSON('ct_datasource', ds);
      ctx.storage.setJSON('ct_raw', { apiData, at: ds.updatedAt || Date.now() });
    } catch (_) {}
    _clearAuthFlag(ctx);
    return ds;
  };

  if (token) {
    try {
      const ds = await _tryFetch(token, cityCode, provinceCode);
      return { configured, ds, fromCache: false, authFailed: false, authError: '' };
    } catch (e) {
      if (e && e.transient) {
        return _fromCache(ctx, configured, settings, false, '');
      }
    }
  }

  try {
    const login = await telecomLogin(ctx, account);
    const ds = await _tryFetch(login.token, login.cityCode, login.provinceCode);
    return { configured, ds, fromCache: false, authFailed: false, authError: '' };
  } catch (e) {
    if (e && e.transient) {
      return _fromCache(ctx, configured, settings, false, '');
    }

    _notifyAuthFailedOnce(ctx, account, e);
    return { configured, ds: null, fromCache: false, authFailed: true, authError: (e && e.message) || '登录失败' };
  }
}

function _fromCache(ctx, configured, settings, authFailed, authError) {
  try {
    const raw = ctx.storage.getJSON('ct_raw');
    if (raw && raw.apiData) {
      const ds = parseImportantData(raw.apiData, settings);
      ds.updatedAt = raw.at || ds.updatedAt;
      return { configured, ds, fromCache: true, authFailed, authError };
    }
  } catch (_) {}
  try {
    const cached = ctx.storage.getJSON('ct_datasource');
    if (cached) return { configured, ds: cached, fromCache: true, authFailed, authError };
  } catch (_) {}
  return { configured, ds: null, fromCache: false, authFailed, authError };
}


const C_FEE = '#FF9F0A';
const C_FLOW = '#0A84FF';
const C_OTHER = '#64D2FF';
const C_VOICE = '#30D158';
const WARN = '#FF453A';
const TXT = { light: '#000000', dark: '#FFFFFF' };
const SUB = { light: '#3C3C4399', dark: '#EBEBF599' };
const GLASS = { light: '#FFFFFFA6', dark: '#FFFFFF1A' };

function bg() {
  return {
    type: 'linear',
    colors: [{ light: '#EAF3FF', dark: '#0B1A33' }, { light: '#F4F0FF', dark: '#120B24' }, { light: '#E9FBF3', dark: '#03140F' }],
    stops: [0, 0.55, 1],
    startPoint: { x: 0, y: 0 },
    endPoint: { x: 1, y: 1 },
  };
}

/* ---------- 用量洞察 ---------- */

function toMB(d) {
  const n = parseFloat(d && d.number);
  if (!Number.isFinite(n)) return null;
  return d.unit === 'GB' ? n * 1024 : n;
}

function fmtMB(mb) {
  if (mb == null || !Number.isFinite(mb)) return '--';
  return mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(0)} MB`;
}

/* ---------- 图形 ---------- */

// 三层同心圆环（外→内：通用流量、其他流量、语音）
function ringsSvg(values, size, stroke, gap) {
  const h = size / 2;
  let body = '';
  values.forEach((v, i) => {
    const r = h - stroke / 2 - i * (stroke + gap);
    if (r <= stroke / 2) return;
    const c = 2 * Math.PI * r;
    const p = Math.max(0, Math.min(1, Number(v.pct) || 0));
    body += `<circle cx='${h}' cy='${h}' r='${r.toFixed(2)}' fill='none' stroke='${v.color}' stroke-opacity='0.22' stroke-width='${stroke}'/>`;
    if (p > 0) {
      // 用 path 圆弧绘制进度，不依赖 stroke-dasharray
      if (p >= 0.999) {
        body += `<circle cx='${h}' cy='${h}' r='${r.toFixed(2)}' fill='none' stroke='${v.color}' stroke-width='${stroke}'/>`;
      } else {
        const a = p * 2 * Math.PI;
        const x = (h + r * Math.sin(a)).toFixed(2), y = (h - r * Math.cos(a)).toFixed(2);
        body += `<path d='M ${h} ${(h - r).toFixed(2)} A ${r.toFixed(2)} ${r.toFixed(2)} 0 ${p > 0.5 ? 1 : 0} 1 ${x} ${y}' fill='none' stroke='${v.color}' stroke-width='${stroke}' stroke-linecap='round'/>`;
      }
    }
  });
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${size} ${size}'>${body}</svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

function ringSvg(pct, size, stroke) {
  return ringsSvg([{ pct, color: 'white' }], size, stroke, 0);
}

function barSvg(pct, color, w, h) {
  const p = Math.max(0, Math.min(1, Number(pct) || 0));
  const r = h / 2, fw = p > 0 ? Math.max(h, w * p) : 0;
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'>` +
    `<rect width='${w}' height='${h}' rx='${r}' fill='${color}' fill-opacity='0.2'/>` +
    (fw ? `<rect width='${fw.toFixed(1)}' height='${h}' rx='${r}' fill='${color}'/>` : '') + `</svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

function sparkSvg(values, color, w, h) {
  const vals = values && values.length ? values : [null, null, null, null, null, null, null];
  const n = vals.length, gap = 3, bw = (w - gap * (n - 1)) / n;
  const max = Math.max(1, ...vals.map(v => v || 0));
  let body = '';
  vals.forEach((v, i) => {
    const bh = v ? Math.max(2, (v / max) * h) : 2;
    const op = v == null ? 0.15 : (i === n - 1 ? 1 : 0.55);
    body += `<rect x='${(i * (bw + gap)).toFixed(1)}' y='${(h - bh).toFixed(1)}' width='${bw.toFixed(1)}' height='${bh.toFixed(1)}' rx='${Math.min(2, bw / 2).toFixed(1)}' fill='${color}' fill-opacity='${op}'/>`;
  });
  return 'data:image/svg+xml,' + encodeURIComponent(`<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'>${body}</svg>`);
}

function ringValues(ds) {
  const o = ds.otherFlow || {};
  return [
    { pct: ds.flow.percent == null ? 0 : ds.flow.percent / 100, color: C_FLOW },
    { pct: o.percent == null ? 0 : o.percent / 100, color: C_OTHER },
    { pct: ds.voice.percent == null ? 0 : ds.voice.percent / 100, color: C_VOICE },
  ];
}

/* ---------- 组件 ---------- */

function t(text, size, weight, color, extra) {
  return Object.assign({ type: 'text', text: String(text), font: { size, weight: weight || 'regular' }, textColor: color || TXT, maxLines: 1, minScale: 0.6 }, extra || {});
}

function header(title, ds, fromCache) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
    children: [
      { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', width: 13, height: 13, color: C_FLOW },
      t(title, 13, 'semibold', null, { minScale: 1 }),
      { type: 'spacer' },
      t(`${fromCache ? '缓存 · ' : ''}更新 ${ds && ds.updatedAt ? fmtTime(ds.updatedAt) : '--'}`, 10, 'regular', SUB, { minScale: 1 }),
    ],
  };
}

function feeBig(ds, ins, size) {
  const color = ins.lowFee ? WARN : TXT;
  return {
    type: 'stack', direction: 'column', alignItems: 'start', gap: 0,
    children: [
      t(ins.lowFee ? '话费不足' : '剩余话费', 'caption2', 'medium', ins.lowFee ? WARN : SUB),
      {
        type: 'stack', direction: 'row', alignItems: 'end', gap: 1,
        children: [
          t('¥', 'subheadline', 'semibold', ins.lowFee ? WARN : SUB),
          t(ds.fee.number, size || 28, 'bold', color),
        ],
      },
    ],
  };
}

function legendRow(icon, color, d, extra) {
  const data = d || { title: '', number: '--', unit: '' };
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 5,
    children: [
      { type: 'image', src: `sf-symbol:${icon}`, width: 12, height: 12, color },
      t(data.title, 'caption1', 'regular', SUB),
      { type: 'spacer' },
      t(data.number, 'subheadline', 'bold', TXT),
      t(data.unit ? ` ${data.unit}` : '', 'caption2', 'regular', SUB),
      ...(extra ? [t(`  ${extra}`, 'caption2', 'semibold', color)] : []),
    ],
  };
}

function alignedRow(icon, color, d, extra) {
  const data = d || { title: '', number: '--', unit: '' };
  const box = (w, child, right) => ({ type: 'stack', direction: 'row', alignItems: 'center', width: w, children: right ? [{ type: 'spacer' }, child] : [child, { type: 'spacer' }] });
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
    children: [
      { type: 'image', src: `sf-symbol:${icon}`, width: 12, height: 12, color },
      t(data.title, 'caption1', 'regular', SUB, { minScale: 0.8 }),
      { type: 'spacer' },
      box(48, t(data.number, 'subheadline', 'bold', TXT, { minScale: 0.7 }), true),
      box(22, t(data.unit || '', 'caption2', 'regular', SUB, { minScale: 0.8 }), false),
      box(30, t(extra || '', 'caption2', 'semibold', color, { minScale: 0.8 }), true),
    ],
  };
}

function pctText(d) { return d && d.percent != null ? `${Math.round(d.percent)}%` : ''; }

function chip(icon, color, text) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 4, padding: [5, 8], borderRadius: 99,
    backgroundColor: GLASS,
    children: [
      { type: 'image', src: `sf-symbol:${icon}`, width: 11, height: 11, color },
      t(text, 'caption2', 'semibold', TXT),
    ],
  };
}

function glass(children, extra) {
  return Object.assign({ type: 'stack', direction: 'column', alignItems: 'start', gap: 6, padding: 12, borderRadius: 22, backgroundColor: GLASS, children }, extra || {});
}

/* ---------- 尺寸 ---------- */

function miniRow(icon, color, d, barW, label) {
  const data = d || { title: '', number: '--', unit: '', percent: 0 };
  return {
    type: 'stack', direction: 'column', alignItems: 'start', gap: 2,
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
        children: [
          { type: 'image', src: `sf-symbol:${icon}`, width: 10, height: 10, color },
          ...(label ? [t(label, 9, 'medium', SUB, { minScale: 1 })] : []),
          { type: 'spacer' },
          t(data.number, 11, 'bold', TXT, { minScale: 0.8 }),
          t(data.unit ? ` ${data.unit}` : '', 9, 'regular', SUB, { minScale: 1 }),
          ...(pctText(data) ? [t(` ${pctText(data)}`, 9, 'semibold', color, { minScale: 1 })] : []),
        ],
      },
      { type: 'image', src: barSvg(data.percent == null ? 0 : data.percent / 100, color, barW + 2, 3), width: barW, height: 3 },
    ],
  };
}

function buildSmall(title, ds, fromCache, ctx) {
  const ins = insights(ctx, ds);
  const other = ds.otherFlow || { title: '其他流量', number: '--', unit: '', percent: 0 };
  return {
    type: 'widget', padding: [12, 13], gap: 4, backgroundGradient: bg(),
    refreshAfter: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    children: [
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
        children: [
          { type: 'image', src: 'sf-symbol:antenna.radiowaves.left.and.right', width: 12, height: 12, color: C_FLOW },
          t(title, 'caption1', 'semibold'),
          { type: 'spacer' },
          t(ds.updatedAt ? fmtTime(ds.updatedAt).slice(-5) : '--', 9, 'regular', SUB, { minScale: 1 }),
        ],
      },
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 9,
        children: [
          { type: 'image', src: ringsSvg(ringValues(ds), 120, 15, 3), width: 56, height: 56 },
          {
            type: 'stack', direction: 'column', alignItems: 'start', gap: 1,
            children: [
              feeBig(ds, ins, 24),
              t(ins.todayMB != null ? `已记录 ${fmtMB(ins.todayMB)}` : `本月剩 ${ins.daysLeft} 天`, 10, 'semibold', C_FLOW, { minScale: 0.8 }),
            ],
          },
          { type: 'spacer' },
        ],
      },
      { type: 'spacer' },
      miniRow('wifi', C_FLOW, ds.flow, 144, ds.flow.title),
      miniRow('globe.asia.australia.fill', C_OTHER, other, 144, other.title),
      miniRow('phone.fill', C_VOICE, ds.voice, 144, ds.voice.title),
    ],
  };
}

function buildMedium(title, ds, fromCache, ctx) {
  const ins = insights(ctx, ds);
  const other = ds.otherFlow || { title: '其他流量', number: '--', unit: '' };
  return {
    type: 'widget', padding: [12, 14], gap: 8, backgroundGradient: bg(),
    refreshAfter: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    children: [
      header(title, ds, fromCache),
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 12, flex: 1,
        children: [
          {
            type: 'stack', direction: 'column', alignItems: 'center', gap: 4, width: 96,
            children: [
              { type: 'image', src: ringsSvg(ringValues(ds), 120, 13, 3), width: 70, height: 70 },
              feeBig(ds, ins, 20),
            ],
          },
          glass([
            alignedRow('wifi', C_FLOW, ds.flow, pctText(ds.flow)),
            alignedRow('globe.asia.australia.fill', C_OTHER, other, pctText(other)),
            alignedRow('phone.fill', C_VOICE, ds.voice, pctText(ds.voice)),
            {
              type: 'stack', direction: 'row', alignItems: 'center', gap: 5,
              children: [
                { type: 'image', src: sparkSvg(ins.hist, C_FLOW, 70, 14), width: 34, height: 10 },
                t(ins.todayMB != null ? `已记录 ${fmtMB(ins.todayMB)}` : `本月剩 ${ins.daysLeft} 天`, 9, 'semibold', TXT, { minScale: 0.8 }),
                { type: 'spacer' },
                t(ins.forecast.text, 9, 'semibold', ins.forecast.color, { minScale: 0.8 }),
              ],
            },
          ], { flex: 1, gap: 7, padding: [10, 12] }),
        ],
      },
      ...(ds.planDebug ? [t(ds.planDebug, 'caption2', 'regular', SUB, { maxLines: 3 })] : []),
    ],
  };
}

function buildLarge(title, ds, fromCache, ctx) {
  const ins = insights(ctx, ds);
  const other = ds.otherFlow || { title: '其他流量', number: '--', unit: '', percent: 0 };
  const phone = (ctx.env || {}).CT_PHONE || '';
  const masked = /^\d{11}$/.test(phone) ? `${phone.slice(0, 3)} **** ${phone.slice(7)}` : '';
  const meter = (icon, color, d) => glass([
    {
      type: 'stack', direction: 'row', alignItems: 'center', gap: 5,
      children: [
        { type: 'image', src: `sf-symbol:${icon}`, width: 13, height: 13, color },
        t(d.title, 'caption1', 'regular', SUB),
        { type: 'spacer' },
        t(d.number, 17, 'bold', TXT),
        t(d.unit ? ` ${d.unit}` : '', 'caption2', 'regular', SUB),
        ...(pctText(d) ? [t(`  ${pctText(d)}`, 'caption1', 'semibold', color)] : []),
      ],
    },
    { type: 'image', src: barSvg(d.percent == null ? 0 : d.percent / 100, color, 300, 6), width: 296, height: 6 },
  ], { gap: 6, padding: [8, 12], borderRadius: 16, height: 48 });
  return {
    type: 'widget', padding: [13, 15], gap: 7, backgroundGradient: bg(),
    refreshAfter: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    children: [
      header(title, ds, fromCache),
      {
        type: 'stack', direction: 'row', alignItems: 'center', gap: 14, height: 80,
        children: [
          { type: 'image', src: ringsSvg(ringValues(ds), 140, 15, 3), width: 78, height: 78 },
          {
            type: 'stack', direction: 'column', alignItems: 'start', gap: 3,
            children: [
              feeBig(ds, ins, 30),
              ...(masked ? [t(masked, 'caption2', 'medium', SUB, { family: 'Menlo' })] : []),
              t(`本月还剩 ${ins.daysLeft} 天${ins.dailyMB != null ? ` · 日均可用约 ${fmtMB(ins.dailyMB)}` : ''}`, 'caption2', 'semibold', C_FLOW),
            ],
          },
          { type: 'spacer' },
        ],
      },
      meter('wifi', C_FLOW, ds.flow),
      meter('globe.asia.australia.fill', C_OTHER, other),
      meter('phone.fill', C_VOICE, ds.voice),
      glass([
        {
          type: 'stack', direction: 'row', alignItems: 'center', gap: 8,
          children: [
            { type: 'image', src: sparkSvg(ins.hist, C_FLOW, 140, 20), width: 120, height: 16 },
            t(`已记录 ${ins.todayMB != null ? fmtMB(ins.todayMB) : '--'}`, 'caption1', 'bold', TXT),
            { type: 'spacer' },
            t(ins.forecast.text, 'caption2', 'semibold', ins.forecast.color),
          ],
        },
      ], { padding: [9, 12], borderRadius: 16, gap: 0, height: 36 }),
      { type: 'spacer' },
      ...(ds.planDebug ? [t(ds.planDebug, 'caption2', 'regular', SUB, { maxLines: 3 })] : []),
    ],
  };
}

function buildLockScreen(title, ds, family, ctx) {
  const ins = insights(ctx, ds);
  if (family === 'accessoryInline') {
    return { type: 'widget', children: [{ type: 'text', text: `¥${ds.fee.number} · ${ds.flow.title}${ds.flow.number}${ds.flow.unit} · ${ds.voice.title}${ds.voice.number}分`, maxLines: 1, minScale: 0.6 }] };
  }
  if (family === 'accessoryCircular') {
    const hasPct = ds.flow && ds.flow.percent != null;
    return {
      type: 'widget', padding: 8, backgroundImage: ringSvg(hasPct ? ds.flow.percent / 100 : 0, 60, 6),
      children: [
        { type: 'spacer' },
        {
          type: 'stack', direction: 'column', alignItems: 'center', gap: 0,
          children: hasPct
            ? [
              { type: 'image', src: 'sf-symbol:wifi', width: 10, height: 10 },
              { type: 'text', text: String(ds.flow.number), font: { size: 14, weight: 'bold' }, textAlign: 'center', maxLines: 1, minScale: 0.5 },
              { type: 'text', text: ds.flow.unit, font: { size: 9 }, textAlign: 'center', opacity: 0.7 },
            ]
            : [
              { type: 'text', text: '¥', font: { size: 9 }, textAlign: 'center', opacity: 0.7 },
              { type: 'text', text: ds.fee.number, font: { size: 14, weight: 'bold' }, textAlign: 'center', maxLines: 1, minScale: 0.5 },
            ],
        },
        { type: 'spacer' },
      ],
    };
  }
  return {
    type: 'widget', padding: [2, 4], gap: 2,
    children: [
      { type: 'text', text: `¥${ds.fee.number}${ins.lowFee ? ' · 话费不足' : ''}`, font: { size: 'footnote', weight: 'bold' }, maxLines: 1, minScale: 0.6 },
      { type: 'text', text: `号内${ds.flow.title} ${ds.flow.number} ${ds.flow.unit} · ${ds.voice.title} ${ds.voice.number}分`, font: { size: 'caption2', weight: 'semibold' }, maxLines: 1, minScale: 0.6 },
      { type: 'text', text: ins.todayMB != null ? `已记录 ${fmtMB(ins.todayMB)} · 日均 ${fmtMB(ins.dailyMB)}` : `还剩 ${ins.daysLeft} 天`, font: { size: 'caption2' }, opacity: 0.7, maxLines: 1, minScale: 0.6 },
    ],
  };
}

function buildError(title, message, extra) {
  const children = [
    t(title, 'footnote', 'semibold'),
    { type: 'spacer' },
    { type: 'image', src: 'sf-symbol:exclamationmark.triangle.fill', width: 22, height: 22, color: C_FEE },
    t(message, 'caption1', 'medium', TXT, { maxLines: 4, minScale: 0.7 }),
  ];
  if (extra) children.push(t(extra, 'caption2', 'regular', SUB, { maxLines: 3 }));
  children.push({ type: 'spacer' });
  return { type: 'widget', padding: 14, gap: 6, backgroundGradient: bg(), children };
}


// 仅适配既有电信查询结果；不发出任何额外网络请求。
function adaptHark(ctx, original, stale) {
  const ds=JSON.parse(JSON.stringify(original));
  ds.stale=!!stale;
  ds.flow.percent=null; ds.voice.percent=null;
  ds.otherFlow={title:'定向流量',number:'--',unit:'',percent:null};
  ds.remainingKB=null; ds.history=[];
  let raw;
  try {raw=ctx.storage.getJSON('ct_raw');} catch (_) {}
  if (!raw || !raw.apiData || Number(raw.at)!==Number(ds.updatedAt)) return ds;
  const a=raw.apiData, f=a.flowInfo || {}, g=f.commonFlow || {}, all=f.totalAmount || {};
  const n=v=>v==null || v==='' || !Number.isFinite(Number(v)) ? null : Number(v);
  const general=[n(g.total),n(g.used),n(g.balance)];
  const used=n(all.used!==undefined ? all.used : a.usedFlux),remain=n(all.balance);
  const total=[n(all.total!==undefined ? all.total : (used!=null && remain!=null ? used+remain : null)),used,remain];
  const hasCommon=g.used!==undefined || g.balance!==undefined || g.total!==undefined;
  const other=total.map((v,i)=>v==null || general[i]==null ? null : Math.max(0,v-general[i]));
  const env=ctx.env || {}, incG=env.CT_SHOW_GENERAL_FLOW!=='false',incD=env.CT_SHOW_DIRECTIONAL_FLOW!=='false';
  const showUsed=env.CT_SHOW_USED_FLOW==='true',suffix=showUsed?'已用':'剩余';
  const percent=(arr,usedMode)=>arr[0]!=null && arr[0]>0 && arr[usedMode?1:2]!=null ? Math.max(0,Math.min(100,arr[usedMode?1:2]/arr[0]*100)) : null;
  const display=(arr,label)=>{
    const val=arr[showUsed?1:2],fmt=val==null?null:formatFlow(val);
    return {title:label+suffix,number:fmt?fmt.amount:'--',unit:fmt?fmt.unit:'',percent:percent(arr,showUsed)};
  };
  let selected=total;
  if(hasCommon && incG && !incD) selected=general;
  if(hasCommon && !incG && incD) selected=other;
  if(hasCommon && incG && incD){
    ds.flow=display(general,'通用');
    ds.otherFlow=display(other,'定向');
  } else {
    ds.flow=display(selected,hasCommon && incG && !incD?'通用':hasCommon && !incG && incD?'定向':'流量');
    ds.otherFlow.title=(hasCommon && !incG && incD?'通用':'定向')+'未计入';
    if(!hasCommon || (!incG && !incD))ds.otherFlow.title='定向暂无明细';
  }
  ds.remainingKB=selected[2];
  const v=(a.voiceInfo || {}).voiceDataInfo || {};
  const vt=n(v.total!==undefined?v.total:a.totalVoice),vu=n(v.used!==undefined?v.used:a.usedVoice);
  const vb=n(v.balance!==undefined?v.balance:vt!=null && vu!=null?vt-vu:null);
  ds.voice.percent=percent([vt,vu,vb],env.CT_SHOW_USED_VOICE==='true');
  if(vb==null && env.CT_SHOW_USED_VOICE!=='true')ds.voice.number='--';
  const key='ct_hark_history_v1',mode=String(incG)+':'+String(incD);
  try {
    const old=ctx.storage.getJSON(key) || [];
    let history=old.filter(x=>x.mode===mode && Number(ds.updatedAt)-Number(x.ts)<8*86400000);
    if(!stale && ds.remainingKB!=null && !history.some(x=>Number(x.ts)===Number(ds.updatedAt))){
      history.push({ts:Number(ds.updatedAt),flowKB:ds.remainingKB,mode});
      history.sort((a,b)=>a.ts-b.ts);history=history.slice(-384);
      ctx.storage.setJSON(key,history);
    }
    ds.history=history;
  } catch(_) {}
  return ds;
}
// 只读已采样的余量；不会把旧数据当作今天的新查询。
function insights(ctx,ds) {
  const now=new Date(),dim=new Date(now.getFullYear(),now.getMonth()+1,0).getDate();
  const daysLeft=dim-now.getDate()+1;
  const key=ts=>{const d=new Date(ts);return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate());};
  const dayKey=key(now.getTime()),hist=[];
  const samples=ds.history || [];
  const daily={};
  for(let i=1;i<samples.length;i++){
    const prev=samples[i-1],cur=samples[i];
    if(key(prev.ts)!==key(cur.ts))continue;
    const k=key(cur.ts),delta=Math.max(0,Number(prev.flowKB)-Number(cur.flowKB))/1024;
    if(Number.isFinite(delta))daily[k]=(daily[k] || 0)+delta;
  }
  for(let i=6;i>=0;i--) {const k=key(now.getTime()-i*86400000);hist.push(daily[k]===undefined?null:daily[k]);}
  const remain=ds.remainingKB==null?null:ds.remainingKB/1024;
  return {hist,forecast:{text:'已记录消耗估算',color:SUB},daysLeft,monthPct:(now.getDate()-1+now.getHours()/24)/dim,todayMB:daily[dayKey]===undefined?null:daily[dayKey],dailyMB:remain==null?null:remain/daysLeft,lowFee:Number.isFinite(parseFloat(ds.fee.number)) && parseFloat(ds.fee.number)<10};
}
async function handleWidget(ctx) {
  ctx=ctx || {};ctx.env=ctx.env || {};
  const title=(ctx.env.CT_TITLE || '中国电信').trim() || '中国电信';
  try {
    const r=await loadData(ctx);
    if(!r.configured)return buildError(title,'请在模块设置里填写手机号和服务密码');
    if(r.authFailed || !r.ds)return buildError(title,r.authError || '数据获取失败，请检查原电信模块参数');
    const ds=adaptHark(ctx,r.ds,r.fromCache),family=ctx.widgetFamily || 'systemSmall';
    if(family==='systemLarge' || family==='systemExtraLarge')return buildLarge(title,ds,r.fromCache,ctx);
    if(family==='systemMedium')return buildMedium(title,ds,r.fromCache,ctx);
    if(family.startsWith('accessory'))return buildLockScreen(title,ds,family,ctx);
    return buildSmall(title,ds,r.fromCache,ctx);
  }catch(e){return buildError(title,'组件显示异常，请保留原版并检查设置');}
}
export default async function(ctx) {
  if(ctx && ctx.request && ctx.request.url)return {type:'text',text:'app login mode, no capture'};
  return handleWidget(ctx);
}
