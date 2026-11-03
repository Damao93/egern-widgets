/* 电信玻璃界面适配版：后端 IBL3ND/module；UI moyuzaime/egern。
 * 仅适配展示，原登录/查询/30分钟缓存保留；不含账号信息。 */
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

function ctFormatFlow(flow) {
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
  const balanceFmt = ctFormatFlow(balanceFlow);
  const usedFmt = ctFormatFlow(used);
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


const C = {
  // 低饱和环境渐变 + 统一中性色玻璃；主题色只用于图标、关键数字和进度。
  fee: '#E28A16',
  flow: '#079ACB',
  voice: '#8B5CF6',
  // 文本色随系统外观自动切换，避免深色模式下深色文字落在深色玻璃上。
  txt: { light: '#172B45', dark: '#F3F7FC' },
  sub: { light: '#586D84', dark: '#B8C7D8' },
  title: '#0F9F91',
  cyan: '#22B8CF',
  violet: '#9B7BFF',
  pink: '#EC6FA7',
  green: '#27A879',
  glass: { light: '#FFFFFFD9', dark: '#263D55D9' },
  glassBorder: { light: '#FFFFFF70', dark: '#FFFFFF25' },
  glassShadow: { light: '#64748B06', dark: '#00000000' },
};

// 测试版采用统一的清透磨砂玻璃，避免不同卡片各自铺色造成视觉杂乱。
const transparentMode = true;

function calcPlanPercent(total, used, remain) {
  const t = Number(total), u = Number(used), r = Number(remain);
  if (Number.isFinite(t) && t > 0 && Number.isFinite(u) && u >= 0) return Math.max(0, Math.min(1, u / t));
  if (Number.isFinite(t) && t > 0 && Number.isFinite(r) && r >= 0) return Math.max(0, Math.min(1, 1 - r / t));
  return null;
}
function formatFlow(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return { number: '--', unit: 'GB' };
  if (n >= 1024 * 1024) return { number: (n / (1024 * 1024)).toFixed(2), unit: 'GB' };
  if (n >= 1024) return { number: (n / 1024).toFixed(2), unit: 'MB' };
  if (n >= 1) return { number: n.toFixed(2), unit: 'KB' };
  return { number: (n * 1024).toFixed(2), unit: 'B' };
}
function formatVoice(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n.toFixed(0) : '--';
}

function fontSize(size) {
  if (typeof size === 'number') {
    if (size <= 8) return 9;
    if (size <= 10) return 10;
    if (size <= 13) return 12;
    if (size <= 19) return 16;
    return 24;
  }

  const named = {
    caption2: 9,
    caption1: 10,
    footnote: 12,
    body: 16,
    title3: 20,
    title2: 22,
    title: 24,
  };
  return named[size] || 12;
}

function t(text, size, weight, color, extra) {
  return Object.assign({
    type: 'text',
    text: String(text),
    font: { size: fontSize(size), weight: weight || 'regular' },
    textColor: color || C.txt,
    maxLines: 1,
    minScale: 0.6,
  }, extra || {});
}

const NO_COLOR = { light: '#00000000', dark: '#00000000' };

function glass(children, extra) {
  // 所有尺寸共用单一外层玻璃；此 helper 只负责透明布局，不再绘制内层卡片。
  // 透明值只作为默认值：调用方显式传入的样式仍然生效（原实现会写死覆盖）。
  return Object.assign({
    type: 'stack',
    direction: 'column',
    gap: 6,
    padding: [8, 10],
    borderRadius: 16,
    backgroundColor: NO_COLOR,
    borderWidth: 0,
    borderColor: NO_COLOR,
    shadowRadius: 0,
    children,
  }, extra || {});
}

function gaugeSvg(pct, color, w) {
  const stroke = 11;
  const r = (w - stroke) / 2;
  const cx = w / 2;
  const cy = w / 2;
  const h = w / 2 + stroke / 2;
  const p = Math.max(0, Math.min(1, Number(pct) || 0));

  const pt = a => [
    (cx - r * Math.cos(a)).toFixed(2),
    (cy - r * Math.sin(a)).toFixed(2),
  ];

  const [x0, y0] = pt(0);
  const [x1, y1] = pt(Math.PI);
  const [xp, yp] = pt(Math.PI * p);

  let body =
    `<path d='M ${x0} ${y0} A ${r} ${r} 0 0 1 ${x1} ${y1}' fill='none' stroke='${color}' stroke-opacity='0.18' stroke-width='${stroke}' stroke-linecap='round'/>`;

  if (p > 0.005) {
    body +=
      `<path d='M ${x0} ${y0} A ${r} ${r} 0 0 1 ${xp} ${yp}' fill='none' stroke='${color}' stroke-width='${stroke}' stroke-linecap='round'/>`;
  }

  return 'data:image/svg+xml,' +
    encodeURIComponent(
      `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'>${body}</svg>`
    );
}

function flowStatus(pct) {
  if (pct == null || !Number.isFinite(Number(pct))) {
    return { color: C.flow, label: '套餐用量' };
  }
  const p = Number(pct);
  if (p >= 0.9) return { color: '#C4475B', label: '用量偏高' };
  if (p >= 0.7) return { color: C.fee, label: '注意余量' };
  return { color: C.voice, label: '用量正常' };
}

function trendStrip(ds) {
  const today = todayFlowUsage(ds.history);
  const used = today.value == null ? null : formatFlow(today.value);
  return glass([
    {
      type: 'stack',
      direction: 'row',
      alignItems: 'center',
      gap: 6,
      children: [
        ...(used
          ? [{
              type: 'image',
              src: historySvg(today.history, C.flow, 100, 30),
              width: 72,
              height: 22,
            }]
          : []),
        {
          type: 'stack',
          direction: 'column',
          alignItems: 'start',
          gap: 1,
          flex: 1,
          children: [
            t('今日已记录消耗', 9, 'semibold', C.txt),
            t(today.label, 8, 'medium', C.sub, { minScale: 0.65 }),
          ],
        },
        ...(used ? [t(used.number + ' ' + used.unit, 9, 'bold', C.flow, { minScale: 0.7 })] : []),
      ],
    },
  ], {
    height: 42,
    padding: [5, 8],
    borderRadius: 13,
    gap: 0,
  });
}

function historySvg(history, color, w, h) {
  const vals = (history || []).map(x => Number(x.flowKB)).filter(Number.isFinite).slice(-12);
  const baseline = h - 2;
  const empty = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'><path d='M 2 ${baseline} H ${w-2}' stroke='${color}' stroke-opacity='.22' stroke-width='1.5' stroke-linecap='round' stroke-dasharray='3 4'/></svg>`;
  if (!vals.length) return 'data:image/svg+xml,' + encodeURIComponent(empty);

  const max = Math.max(1, ...vals);
  const padX = Math.min(3, w * 0.025);
  const gap = Math.max(2, Math.min(5, w * 0.035));
  const count = vals.length;
  const barW = Math.max(2, (w - padX * 2 - gap * (count - 1)) / count);
  const usableH = h - 5;
  const bars = vals.map((v, i) => {
    const bh = Math.max(2, (Math.max(0, v) / max) * usableH);
    const x = padX + i * (barW + gap);
    const y = baseline - bh;
    const opacity = i === count - 1 ? 1 : 0.48 + 0.42 * ((i + 1) / count);
    return `<rect x='${x.toFixed(1)}' y='${y.toFixed(1)}' width='${barW.toFixed(1)}' height='${bh.toFixed(1)}' rx='${Math.min(2, barW / 2).toFixed(1)}' fill='${color}' fill-opacity='${opacity.toFixed(2)}'/>`;
  }).join('');
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ${w} ${h}'><path d='M 1 ${baseline} H ${w-1}' stroke='${color}' stroke-opacity='.12' stroke-width='1'/>${bars}</svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

function heroFlowCard(ds, cardHeight, cardFlex, isMedium) {
  const remain = ds.flow.number + ' ' + ds.flow.unit;
  const total = ds.plan && ds.plan.total != null ? formatFlow(ds.plan.total) : null;
  const used = ds.plan && ds.plan.used != null ? formatFlow(ds.plan.used) : null;
  const compactFlowDetail = !cardHeight
    ? '总量 ' + (total ? total.number + ' ' + total.unit : '--') + ' · 已用 ' + (used ? used.number + ' ' + used.unit : '--') +
      (ds.directional && ds.directional.remain
        ? ' · 定向 ' + ds.directional.remain.number + ' ' + ds.directional.remain.unit
        : '')
    : '';
  const p = ds.plan && ds.plan.percent != null ? ds.plan.percent : null;
  const flowStyle = flowStatus(p);
  const flowContent = isMedium
    ? {
        // 中号：左侧显示剩余数值和套餐详情，右侧显示缩小的半圆仪表盘。
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 6,
        children: [
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'start',
            gap: 2,
            flex: 1,
            children: [
              t(remain, cardHeight ? 22 : 19, 'bold', C.txt, { minScale: 0.55 }),
              t(compactFlowDetail || ds.flow.title || '剩余流量', 8, 'medium', C.sub, { minScale: 0.45 }),
            ],
          },
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'center',
            gap: 0,
            children: [
              {
                type: 'image',
                src: gaugeSvg(p != null ? p : 0, flowStyle.color, 68),
                width: 44,
                height: 24,
              },
              t(p != null ? Math.round(p * 100) + '% 已用' : '—', 8, 'bold', flowStyle.color),
            ],
          },
        ],
      }
    : {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 12,
        children: [
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'center',
            gap: -2,
            children: [
              {
                type: 'image',
                src: gaugeSvg(p != null ? p : 0, flowStyle.color, 86),
                width: 64,
                height: 34,
              },
              t(p != null ? Math.round(p * 100) + '% 已用' : '—', 10, 'bold', flowStyle.color),
            ],
          },
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'start',
            gap: 1,
            flex: 1,
            children: [
              t(remain, cardHeight ? 23 : 20, 'bold', C.txt, { minScale: 0.55 }),
              t(ds.flow.title || '剩余流量', 9, 'medium', C.sub),
              ...(!cardHeight ? [t(compactFlowDetail, 8, 'medium', C.sub, { minScale: 0.45 })] : []),
            ],
          },
        ],
      };
  return glass([
    {
      type: 'stack',
      direction: 'row',
      alignItems: 'center',
      gap: 6,
      children: [
        {
          type: 'image',
          src: 'sf-symbol:chart.pie.fill',
          width: 13,
          height: 13,
          color: C.flow,
        },
        t(ds.packageName || '流量主卡', 10, 'semibold', C.txt),
        { type: 'spacer' },
        t(p != null ? Math.round((1 - p) * 100) + '% 剩余' : '实时套餐', 9, 'semibold', flowStyle.color),
      ],
    },
    flowContent,
  ], {
    width: 0,
    flex: cardFlex || 1,
    ...(cardHeight ? { height: cardHeight, maxWidth: 360 } : {}),
    padding: [8, 10],
    borderRadius: 18,
    gap: 4,
    shadowColor: { light: '#52677A18', dark: '#00000028' },
    shadowRadius: 0,
    shadowOffset: { x: 0, y: 0 },
  });
}

function header(title, ds, fromCache, mediumInset) {
  const dur = ds.captureDuration ? ' · 凭据保持 ' + ds.captureDuration : '';
  return {
    type: 'stack',
    direction: 'row',
    alignItems: 'center',
    padding: mediumInset ? [4, 6] : 0,
    gap: 5,
    children: [
      {
        type: 'image',
        src: 'sf-symbol:antenna.radiowaves.left.and.right',
        width: 13,
        height: 13,
        color: C.flow,
      },
      t(title, 'footnote', 'semibold', C.txt),
      { type: 'spacer' },
      t(`${fromCache ? '缓存数据' : '更新'} ${fmtTime(ds.updatedAt)}${dur}${ds.authFailed ? ' · 凭据待更新' : ''}`, 9, 'medium', C.sub, {
        minScale: 0.8,
      }),
    ],
  };
}

function buildSmall(title, ds, fromCache) {
  const p = ds.plan && ds.plan.percent != null ? ds.plan.percent : null;
  const flowStyle = flowStatus(p);
  const remain = ds.flow.number + ' ' + ds.flow.unit;
  const usedFlow = ds.plan && ds.plan.used != null ? formatFlow(ds.plan.used) : null;
  const totalFlow = ds.plan && ds.plan.total != null ? formatFlow(ds.plan.total) : null;
  const used = usedFlow ? usedFlow.number + ' ' + usedFlow.unit : '--';
  const total = totalFlow ? totalFlow.number + ' ' + totalFlow.unit : '--';

  return {
    type: 'widget',
    padding: [13, 13],
    gap: 6,
    backgroundColor: '#00000000',
    refreshAfter: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    children: [
      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 5,
        children: [
          {
            type: 'image',
            src: 'sf-symbol:antenna.radiowaves.left.and.right',
            width: 12,
            height: 12,
            color: C.flow,
          },
          t(title, 12, 'semibold', C.txt),
          { type: 'spacer' },
          t(`${fromCache ? '缓存 · ' : ''}${fmtTime(ds.updatedAt)}${ds.authFailed ? ' · 凭据待更新' : (ds.captureDuration ? ' · ' + ds.captureDuration : '')}`, 8, 'medium', C.sub, { minScale: 0.5 }),
        ],
      },

      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 4,
        flex: 1,
        children: [
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'start',
            gap: 2,
            flex: 1,
            children: [
              t(ds.packageName || (ds.flow && ds.flow.title) || '剩余流量', 9, 'medium', C.sub),
              {
                type: 'stack',
                direction: 'row',
                alignItems: 'end',
                gap: 2,
                children: [
                  t(ds.flow.number, 23, 'bold', C.txt, { minScale: 0.35 }),
                  t(ds.flow.unit, 9, 'semibold', C.sub, { minScale: 0.7 }),
                ],
              },
              {
                type: 'stack',
                direction: 'column',
                alignItems: 'start',
                gap: 2,
                children: [
                  t(
                    ds.plan && ds.plan.used != null
                      ? '已用 ' + used
                      : '已用量待确认',
                    8,
                    'semibold',
                    flowStyle.color,
                    { minScale: 0.65 }
                  ),
                  t(
                    ds.plan && ds.plan.total != null
                      ? '总量 ' + total
                      : (ds.plan && ds.plan.remain != null
                        ? '余量 ' + formatFlow(ds.plan.remain).number + ' ' + formatFlow(ds.plan.remain).unit
                        : '总量待确认'),
                    8,
                    'medium',
                    C.sub,
                    { minScale: 0.45 }
                  ),
                ],
              },
            ],
          },
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'center',
            gap: -2,
            children: [
              {
                type: 'image',
                src: gaugeSvg(p, flowStyle.color, 78),
                width: 44,
                height: 27,
              },
              t(
                p != null ? Math.round(p * 100) + '% 已用' : '套餐',
                8,
                'bold',
                flowStyle.color
              ),
              t(
                (() => {
                  const today = todayFlowUsage(ds.history);
                  return today.value != null
                    ? '今日 ' + formatFlow(today.value).number + formatFlow(today.value).unit
                    : '今日采集中';
                })(),
                8,
                'medium',
                C.sub,
                { minScale: 0.6 }
              ),
            ],
          },
        ],
      },

      {
        type: 'stack',
        direction: 'row',
        gap: 5,
        children: [
          glass([
            { type: 'stack', direction: 'row', alignItems: 'center', gap: 3, children: [
              { type: 'image', src: 'sf-symbol:phone.fill', width: 10, height: 10, color: C.voice },
              t(ds.voice.title || '剩余语音', 8, 'medium', C.sub),
            ]},
            { type: 'stack', direction: 'row', alignItems: 'end', gap: 2, children: [
              t(ds.voice.number === '--' ? '暂无' : ds.voice.number, 18, 'bold', C.txt, { minScale: 0.4 }),
              t(ds.voice.number === '--' ? '' : '分钟', 8, 'semibold', C.sub),
            ]},
          ], { width: 0, flex: 1, height: 48, padding: [7, 7], gap: 4, borderRadius: 15 }),
          glass([
            { type: 'stack', direction: 'row', alignItems: 'center', gap: 3, children: [
              { type: 'image', src: 'sf-symbol:yensign.circle.fill', width: 10, height: 10, color: C.fee },
              t(ds.account && ds.account.balance != null ? '账户余额' : '剩余话费', 8, 'medium', C.sub),
            ]},
            { type: 'stack', direction: 'row', alignItems: 'end', gap: 2, children: [
              t('¥', 10, 'semibold', C.fee),
              t(ds.fee.number, 18, 'bold', C.txt, { minScale: 0.4 }),
              ...(ds.account && ds.account.monthCost != null
                ? [t('本月 ' + Number(ds.account.monthCost).toFixed(2), 7, 'medium', C.sub, { minScale: 0.5 })]
                : []),
            ]},
          ], { width: 0, flex: 1, height: 48, padding: [7, 7], gap: 4, borderRadius: 15 }),
        ],
      }
    ],
  };
}

function buildMedium(title, ds, fromCache) {
  // 中号内容增加内缩留白，避免标题与信息区贴近玻璃卡片边缘。
  const compactFee = glass([
    {
      type: 'stack',
      direction: 'row',
      alignItems: 'center',
      gap: 4,
      children: [
        {
          type: 'image',
          src: 'sf-symbol:yensign.circle.fill',
          width: 10,
          height: 10,
          color: C.fee,
        },
        t(ds.account && ds.account.balance != null ? '余额' : '话费', 9, 'medium', C.sub),
        { type: 'spacer' },
        {
          type: 'stack',
          direction: 'column',
          alignItems: 'end',
          gap: 0,
          children: [
            t('¥' + ds.fee.number, 15, 'bold', C.txt, { minScale: 0.6 }),
            ...(ds.account && ds.account.monthCost != null
              ? [t('本月 ' + Number(ds.account.monthCost).toFixed(2), 7, 'medium', C.sub, { minScale: 0.5 })]
              : []),
          ],
        },
      ],
    },
  ], {
    flex: 1,
    padding: [6, 8],
    gap: 1,
    borderRadius: 14,
    justifyContent: 'center',
  });

  const compactVoice = glass([
    {
      type: 'stack',
      direction: 'row',
      alignItems: 'center',
      gap: 4,
      children: [
        {
          type: 'image',
          src: 'sf-symbol:phone.fill',
          width: 10,
          height: 10,
          color: C.voice,
        },
        t(ds.voice.title || '语音', 9, 'medium', C.sub),
        { type: 'spacer' },
        t(ds.voice.number, 15, 'bold', C.txt, { minScale: 0.6 }),
        t('分', 8, 'semibold', C.sub),
      ],
    },

  ], {
    flex: 1,
    padding: [6, 8],
    gap: 1,
    borderRadius: 14,
  });

  const row = {
    type: 'stack',
    direction: 'row',
    alignItems: 'center',
    gap: 5,
    children: [
      heroFlowCard(ds, null, null, true),
      {
        type: 'stack',
        direction: 'column',
        alignItems: 'center',
        gap: 5,
        width: 100,
        children: [
          compactFee,
          compactVoice,
        ],
      },
    ],
  };

  return {
    type: 'widget',
    padding: [12, 14],
    gap: 6,
    backgroundColor: { light: '#F4F7FB', dark: '#161B22' },
    refreshAfter: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    children: [
      header(title, ds, fromCache, true),
      row,
      trendStrip(ds),
    ],
  };
}


function todayFlowUsage(history) {
  const now = new Date();
  const todayKey = now.getFullYear() + '-' + (now.getMonth() + 1) + '-' + now.getDate();
  const today = (history || [])
    .filter(x => {
      const ts = Number(x.ts);
      if (!Number.isFinite(ts)) return false;
      const d = new Date(ts);
      return d.getFullYear() + '-' + (d.getMonth() + 1) + '-' + d.getDate() === todayKey;
    })
    .sort((a, b) => Number(a.ts) - Number(b.ts));

  if (today.length < 2) {
    return { value: null, history: today, label: '今日数据采集中' };
  }

  const first = Number(today[0].flowKB);
  const last = Number(today[today.length - 1].flowKB);
  if (!Number.isFinite(first) || !Number.isFinite(last)) {
    return { value: null, history: today, label: '今日数据采集中' };
  }

  const value = Math.max(0, first - last);
  return {
    value,
    history: today.map(x => ({
      ts: x.ts,
      flowKB: Math.max(0, first - Number(x.flowKB)),
    })),
    label: value < 1 ? '今日暂无明显消耗' : '按今日已记录余量变化估算',
  };
}

function buildLarge(title, ds, fromCache) {
  const plan = ds.plan || {};
  const total = plan.total != null ? formatFlow(plan.total) : null;
  const usedFlow = plan.used != null ? formatFlow(plan.used) : null;
  const remain = plan.remain != null ? formatFlow(plan.remain) : null;
  const voicePct = plan.voicePercent != null
    ? Math.max(0, Math.min(1, Number(plan.voicePercent)))
    : null;
  const voiceUsed = plan.voiceUsed != null ? formatVoice(plan.voiceUsed) : null;
  const voiceTotal = plan.voiceTotal != null ? formatVoice(plan.voiceTotal) : null;
  const p = plan.percent != null ? Math.max(0, Math.min(1, Number(plan.percent))) : null;
  const flowStyle = flowStatus(p);
  const today = todayFlowUsage(ds.history);
  const todayUsed = today.value == null ? null : formatFlow(today.value);

  // 大号组件内部只排版内容，不创建子卡片；玻璃背景由 liquidGlassWidget 统一提供。
  return {
    type: 'widget',
    padding: [16, 17],
    gap: 9,
    backgroundColor: '#00000000',
    refreshAfter: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    children: [
      header(title, ds, fromCache),
      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 12,
        height: 112,
        children: [
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'start',
            justifyContent: 'center',
            gap: 7,
            flex: 1.25,
            children: [
              {
                type: 'stack',
                direction: 'row',
                alignItems: 'center',
                gap: 5,
                children: [
                  { type: 'image', src: 'sf-symbol:chart.pie.fill', width: 13, height: 13, color: C.flow },
                  t(ds.packageName || (ds.flow && ds.flow.title) || '剩余流量', 10, 'semibold', C.sub),
                  { type: 'spacer' },
                  t(p != null ? Math.round((1 - p) * 100) + '% 剩余' : '套餐流量', 9, 'semibold', flowStyle.color),
                ],
              },
              {
                type: 'stack',
                direction: 'row',
                alignItems: 'end',
                gap: 3,
                children: [
                  t(ds.flow.number, 29, 'bold', C.txt, { minScale: 0.45 }),
                  t(ds.flow.unit, 11, 'semibold', C.sub),
                ],
              },
              {
                type: 'stack',
                direction: 'row',
                gap: 4,
                height: 5,
                children: [
                  {
                    type: 'stack',
                    flex: p == null ? 1 : Math.max(0.03, p),
                    backgroundColor: flowStyle.color,
                    borderRadius: 4,
                    children: [],
                  },
                  {
                    type: 'stack',
                    flex: p == null ? 0.001 : Math.max(0.03, 1 - p),
                    backgroundColor: { light: '#7890A52B', dark: '#FFFFFF2B' },
                    borderRadius: 4,
                    children: [],
                  },
                ],
              },
              t('总量 ' + (total ? total.number + ' ' + total.unit : '--') +
                '  ·  已用 ' + (usedFlow ? usedFlow.number + ' ' + usedFlow.unit : '--') +
                (ds.otherUsedMB != null
                  ? '  ·  其他 ' + formatFlow(ds.otherUsedMB * 1024).number + ' ' + formatFlow(ds.otherUsedMB * 1024).unit
                  : ''), 9, 'medium', C.sub, { minScale: 0.55 }),
              ...(ds.directional && (ds.directional.remain || ds.directional.used)
                ? [t('定向流量 ' + (ds.directional.remain ? '剩余 ' + ds.directional.remain.number + ' ' + ds.directional.remain.unit : '') +
                    (ds.directional.used ? (ds.directional.remain ? ' · ' : '') + '已用 ' + ds.directional.used.number + ' ' + ds.directional.used.unit : ''), 8, 'medium', C.sub, { minScale: 0.6 })]
                : []),
            ],
          },
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 0,
            width: 90,
            children: [
              { type: 'image', src: gaugeSvg(p, flowStyle.color, 110), width: 76, height: 40 },
              t(p != null ? Math.round(p * 100) + '% 已用' : '用量统计', 9, 'bold', flowStyle.color),
            ],
          },
        ],
      },
      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 10,
        padding: [8, 0],
        children: [
          {
            type: 'stack',
            direction: 'column',
            gap: 4,
            flex: 1,
            children: [
              { type: 'stack', direction: 'row', alignItems: 'center', gap: 4, children: [
                { type: 'image', src: 'sf-symbol:yensign.circle.fill', width: 12, height: 12, color: C.fee },
                t(ds.account && ds.account.balance != null ? '账户余额' : '剩余话费', 10, 'medium', C.sub),
              ]},
              { type: 'stack', direction: 'row', alignItems: 'end', gap: 2, children: [
                t('¥' + ds.fee.number, 21, 'bold', C.txt, { minScale: 0.5 }),
                t('元', 9, 'medium', C.sub),
              ]},
              ...(ds.account && ds.account.monthCost != null
                ? [t('本月 ¥' + Number(ds.account.monthCost).toFixed(2), 8, 'medium', C.sub, { minScale: 0.6 })]
                : []),
            ],
          },
          {
            type: 'stack',
            direction: 'column',
            gap: 4,
            flex: 1,
            children: [
              { type: 'stack', direction: 'row', alignItems: 'center', gap: 4, children: [
                { type: 'image', src: 'sf-symbol:phone.fill', width: 12, height: 12, color: C.voice },
                t(ds.voice.title || '剩余语音', 10, 'medium', C.sub),
              ]},
              { type: 'stack', direction: 'row', alignItems: 'end', gap: 2, children: [
                t(ds.voice.number === '--' ? '暂无' : ds.voice.number, 21, 'bold', C.txt, { minScale: 0.5 }),
                t(ds.voice.number === '--' ? '' : '分钟', 9, 'medium', C.sub),
              ]},
              ...(voiceUsed != null && voiceTotal != null
                ? [t('已用 ' + voiceUsed + ' / ' + voiceTotal + ' 分钟', 8, 'medium', C.sub, { minScale: 0.55 })]
                : (ds.smsRemain != null
                    ? [t('短信 ' + ds.smsRemain + ' 条', 8, 'medium', C.sub, { minScale: 0.55 })]
                    : [])),
            ],
          },
        ],
      },
      {
        type: 'stack',
        direction: 'column',
        gap: 5,
        padding: [7, 0, 0, 0],
        children: [
          {
            type: 'stack',
            direction: 'row',
            alignItems: 'center',
            gap: 4,
            children: [
              { type: 'image', src: 'sf-symbol:chart.bar.fill', width: 10, height: 10, color: C.flow },
              t('今日已记录消耗', 10, 'semibold', C.txt),
              { type: 'spacer' },
              ...(todayUsed ? [t(todayUsed.number + ' ' + todayUsed.unit, 10, 'bold', C.flow)] : []),
            ],
          },
          ...(todayUsed
            ? [{
                type: 'image',
                src: historySvg(today.history.map(x => ({ flowKB: x.flowKB })), C.flow, 270, 38),
                width: 270,
                height: 38,
              }]
            : []),
          t(today.label, 8, 'medium', C.sub),
          {
            type: 'stack',
            direction: 'row',
            alignItems: 'center',
            gap: 4,
            children: [
              { type: 'image', src: 'sf-symbol:clock', width: 9, height: 9, color: C.sub },
              t(fromCache ? '上次成功数据' : '查询数据（30分钟复用）', 8, 'medium', C.sub),
              { type: 'spacer' },
              t(ds.captureDuration ? '凭据已保持 ' + ds.captureDuration : (fromCache ? '数据可能过期' : ''), 8, 'medium', C.sub),
            ],
          },
          ...(ds.account && ds.account.balance != null
            ? [{
                type: 'stack',
                direction: 'row',
                alignItems: 'center',
                gap: 4,
                children: [
                  { type: 'image', src: 'sf-symbol:wallet.pass.fill', width: 9, height: 9, color: C.fee },
                  t('结转 ¥' + (ds.account.carryOver != null ? Number(ds.account.carryOver).toFixed(2) : '--'), 8, 'semibold', C.sub),
                  { type: 'spacer' },
                  ds.account.owed != null && Number(ds.account.owed) > 0
                    ? t('欠费 ¥' + Number(ds.account.owed).toFixed(2), 8, 'semibold', C.fee)
                    : t('无欠费', 8, 'medium', C.sub),
                ],
              }]
            : []),
        ],
      },
    ],
  };
}

function buildLock(title, ds, family) {
  const dur = ds.captureDuration ? ' · 保持' + ds.captureDuration : '';
  if (family === 'accessoryInline') {
    return {
      type: 'widget',
      children: [
        {
          type: 'text',
          text: `¥${ds.fee.number} · ${ds.flow.title}${ds.flow.number}${ds.flow.unit} · ${ds.voice.title}${ds.voice.number}分${dur}`,
          maxLines: 1,
          minScale: 0.6,
        },
      ],
    };
  }

  if (family === 'accessoryCircular') {
    return {
      type: 'widget',
      padding: 7,
      children: [
        { type: 'spacer' },
        {
          type: 'stack',
          direction: 'column',
          alignItems: 'center',
          gap: 0,
          children: [
            {
              type: 'image',
              src: 'sf-symbol:wifi',
              width: 11,
              height: 11,
              color: C.flow,
            },
            t(ds.flow.number, 14, 'bold', C.txt, { minScale: 0.5 }),
            t(ds.flow.unit, 8, 'regular', C.sub),
          ],
        },
        { type: 'spacer' },
      ],
    };
  }

  return {
    type: 'widget',
    padding: [3, 5],
    gap: 2,
    children: [
      t(`话费 ¥${ds.fee.number}`, 'footnote', 'bold', C.fee),
      t(`${ds.flow.title} ${ds.flow.number}${ds.flow.unit} · ${ds.voice.title} ${ds.voice.number}分${dur}`, 'caption2', 'semibold', C.txt, {
        minScale: 0.6,
      }),
    ],
  };
}

function liquidGlassWidget(widget) {
  if (!widget || widget.type !== 'widget') return widget;
  // 透明模式下根节点完全透明，避免系统底色覆盖壁纸；内容仍按各自颜色绘制。
  widget.backgroundColor = transparentMode
    ? '#00000000'
    : { light: '#F4F7FB', dark: '#161B22' };
  delete widget.glassContentPadding;
  return widget;
}

function buildError(title, message) {
  return {
    type: 'widget',
    padding: 14,
    gap: 6,
    backgroundColor: transparentMode ? '#00000000' : { light: '#F4F7FB', dark: '#161B22' },
    children: [
      t(title, 'footnote', 'semibold'),
      { type: 'spacer' },
      {
        type: 'image',
        src: 'sf-symbol:exclamationmark.triangle.fill',
        width: 22,
        height: 22,
        color: C.fee,
      },
      t(message, 'caption1', 'medium', C.txt, {
        maxLines: 4,
        minScale: 0.7,
      }),
      { type: 'spacer' },
    ],
  };
}



// 仅从原脚本已获取的数据补齐界面；不增加接口、登录或请求。
function adaptTelecom(ctx, original, stale) {
  const ds = JSON.parse(JSON.stringify(original));
  ds.stale = stale;
  ds.history = [];
  ds.plan = {total:null,used:null,remain:null,percent:null,voiceTotal:null,voiceUsed:null,voiceRemain:null,voicePercent:null};
  let raw;
  try { raw = ctx.storage.getJSON('ct_raw'); } catch (_) {}
  // 不用不同时间的原始数据覆盖旧缓存。
  if (!raw || !raw.apiData || Number(raw.at) !== Number(ds.updatedAt)) return ds;
  const a = raw.apiData;
  const n = v => v == null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v);
  const f = a.flowInfo || {}, common = f.commonFlow || {}, total = f.totalAmount || {};
  const g = [n(common.total),n(common.used),n(common.balance)];
  const u = n(total.used !== undefined ? total.used : a.usedFlux);
  const b = n(total.balance);
  const t = n(total.total !== undefined ? total.total : (u != null && b != null ? u + b : null));
  const hasCommon = common.used !== undefined || common.balance !== undefined || common.total !== undefined;
  const env = ctx.env || {};
  const general = env.CT_SHOW_GENERAL_FLOW !== 'false', directional = env.CT_SHOW_DIRECTIONAL_FLOW !== 'false';
  let selected = [t,u,b];
  if (hasCommon && general && !directional) selected = g;
  if (hasCommon && !general && directional) selected = [t,u,b].map((v,i) => v == null || g[i] == null ? null : Math.max(0,v-g[i]));
  const voice = (a.voiceInfo || {}).voiceDataInfo || {};
  const vt = n(voice.total !== undefined ? voice.total : a.totalVoice);
  const vu = n(voice.used !== undefined ? voice.used : a.usedVoice);
  const vb = n(voice.balance !== undefined ? voice.balance : (vt != null && vu != null ? vt-vu : null));
  const pct = (total,used,remain) => total == null || total <= 0 ? null : used != null ? Math.max(0,Math.min(1,used/total)) : remain != null ? Math.max(0,Math.min(1,1-remain/total)) : null;
  ds.plan = {total:selected[0],used:selected[1],remain:selected[2],percent:pct(...selected),voiceTotal:vt,voiceUsed:vu,voiceRemain:vb,voicePercent:pct(vt,vu,vb)};
  // 不把故障回退的旧数据记成新采样；按原始查询时刻去重。
  const key = 'ct_glass_history_v1';
  try {
    const history = ctx.storage.getJSON(key) || [];
    const mode = String(general) + ':' + String(directional);
    let next = history.filter(x => x.mode === mode && Number(ds.updatedAt)-Number(x.ts) < 7*86400000);
    if (!stale && selected[2] != null && !next.some(x => Number(x.ts) === Number(ds.updatedAt))) {
      next.push({ts:Number(ds.updatedAt),flowKB:selected[2],mode});
      next.sort((a,b)=>a.ts-b.ts);
      next=next.slice(-96);
      ctx.storage.setJSON(key,next);
    }
    ds.history=next;
  } catch (_) {}
  return ds;
}
async function handleWidget(ctx) {
  ctx = ctx || {};
  ctx.env = ctx.env || {};
  const title = (ctx.env.CT_TITLE || '中国电信').trim() || '中国电信';
  try {
    const result = await loadData(ctx);
    if (!result.configured) return buildError(title,'请在原模块设置里填写手机号和服务密码');
    if (result.authFailed || !result.ds) return buildError(title,result.authError || '数据获取失败，请检查原模块设置');
    const ds = adaptTelecom(ctx,result.ds,result.fromCache);
    const family = ctx.widgetFamily || 'systemSmall';
    if (family === 'systemMedium') return liquidGlassWidget(buildMedium(title,ds,result.fromCache));
    if (family === 'systemLarge' || family === 'systemExtraLarge') return liquidGlassWidget(buildLarge(title,ds,result.fromCache));
    if (family.startsWith('accessory')) return buildLock(title,ds,family);
    return liquidGlassWidget(buildSmall(title,ds,result.fromCache));
  } catch (e) { return buildError(title,'组件显示异常，请保留原版并检查设置'); }
}
export default async function(ctx) {
  if (ctx && ctx.request && ctx.request.url) return {type:'text',text:'app login mode, no capture'};
  return handleWidget(ctx);
}
