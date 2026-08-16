/* ============================================================
   vpsmon 仪表盘前端逻辑
   - token 管理（URL ?token= → localStorage → X-Token 头；401 弹窗）
   - 每 5s 轮询 /api/status + /api/traffic/live；月度图进入时加载一次
   - ECharts：速率折线图 / 月度柱状图 / CPU·内存·磁盘 gauge
   - 数字自适应单位（B/KB/MB/GB/TB；速率加 /s），中文界面
   ============================================================ */
(function () {
  'use strict';

  var API_BASE = '/api';
  var LS_KEY = 'vpsmon_token';
  var POLL_MS = 5000;

  var $ = function (id) { return document.getElementById(id); };

  /* ---------- 单位换算 ---------- */
  var BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];
  var RATE_UNITS = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'];

  function fmtParts(v, units) {
    if (!isFinite(v) || v < 0) v = 0;
    var i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    var digits = (i === 0 || v >= 100) ? 0 : (v >= 10 ? 1 : 2);
    return { value: v.toFixed(digits), unit: units[i] };
  }
  function fmtBytes(v) { var p = fmtParts(v, BYTE_UNITS); return p.value + ' ' + p.unit; }
  function fmtRate(v) { var p = fmtParts(v, RATE_UNITS); return p.value + ' ' + p.unit; }
  function fmtRateAxis(v) { var p = fmtParts(v, RATE_UNITS); return p.value + p.unit; }
  function fmtBytesAxis(v) { var p = fmtParts(v, BYTE_UNITS); return p.value + p.unit; }
  function fmtClock(ts) {
    return new Date(ts * 1000).toLocaleTimeString('zh-CN', { hour12: false });
  }
  function fmtUptime(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + ' 天 ' + h + ' 小时';
    if (h > 0) return h + ' 小时 ' + m + ' 分';
    if (m > 0) return m + ' 分 ' + (sec % 60) + ' 秒';
    return sec + ' 秒';
  }
  function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }

  /* ---------- token 管理 ---------- */
  var token = (function () {
    var t = '';
    try { t = localStorage.getItem(LS_KEY) || ''; } catch (e) { /* 隐私模式 */ }
    var q = new URLSearchParams(location.search);
    var fromUrl = q.get('token');
    if (fromUrl) {
      t = fromUrl;
      try { localStorage.setItem(LS_KEY, t); } catch (e) {}
      q.delete('token');
      var s = q.toString();
      history.replaceState(null, '', location.pathname + (s ? '?' + s : ''));
    }
    return t;
  })();

  var tokenInput = $('token-input');
  tokenInput.value = token;

  $('token-save').addEventListener('click', function () {
    token = tokenInput.value.trim();
    try { localStorage.setItem(LS_KEY, token); } catch (e) {}
    refreshAll();
    loadMonthly();
  });
  $('token-clear').addEventListener('click', function () {
    token = '';
    try { localStorage.removeItem(LS_KEY); } catch (e) {}
    tokenInput.value = '';
    refreshAll();
    loadMonthly();
  });

  /* ---------- 401 弹窗 ---------- */
  function showTokenModal() {
    $('token-modal').hidden = false;
    var inp = $('modal-token-input');
    inp.value = token;
    setTimeout(function () { inp.focus(); }, 60);
  }
  $('modal-token-save').addEventListener('click', function () {
    token = $('modal-token-input').value.trim();
    try { localStorage.setItem(LS_KEY, token); } catch (e) {}
    $('token-modal').hidden = true;
    tokenInput.value = token;
    refreshAll();
    loadMonthly();
  });
  $('modal-token-cancel').addEventListener('click', function () {
    $('token-modal').hidden = true;
  });
  $('modal-token-input').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') $('modal-token-save').click();
  });

  /* ---------- API ---------- */
  function apiGet(path) {
    var headers = { Accept: 'application/json' };
    if (token) headers['X-Token'] = token;
    var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = null;
    if (ctrl) {
      timer = setTimeout(function () { ctrl.abort(); }, 8000);
    }
    return fetch(API_BASE + path, {
      headers: headers,
      cache: 'no-store',
      signal: ctrl ? ctrl.signal : undefined
    })
      .then(function (resp) {
        if (resp.status === 401) {
          showTokenModal();
          throw Object.assign(new Error('unauthorized'), { code: 'unauthorized' });
        }
        return resp.json().catch(function () {
          throw new Error('响应解析失败');
        });
      })
      .then(function (json) {
        if (timer) clearTimeout(timer);
        if (!json || json.ok !== true) {
          throw new Error((json && json.error) ? json.error : '请求失败');
        }
        return json.data;
      })
      .catch(function (e) {
        if (timer) clearTimeout(timer);
        if (e && e.code) throw e;
        throw Object.assign(new Error('网络错误'), { code: 'network' });
      });
  }

  /* ---------- 顶部信息 ---------- */
  $('host-addr').textContent = location.host;
  document.title = 'VPS 流量监控 · ' + location.host;

  function renderStatus(s) {
    $('iface-name').textContent = s.iface || '--';
    $('footer-iface').textContent = s.iface || '--';
    $('uptime').textContent = fmtUptime(s.uptime);
    $('update-time').textContent = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    $('footer-meta').textContent = '样本 ' + (s.sample_count || 0) + ' · 数据库 ' + fmtBytes(s.db_bytes || 0);

    var cpu = clamp(s.cpu || 0, 0, 100);
    $('cpu-value').textContent = cpu.toFixed(1) + '%';
    $('cpu-bar').style.width = cpu.toFixed(1) + '%';

    var memPct = (s.mem && s.mem.total > 0) ? (s.mem.used / s.mem.total * 100) : 0;
    $('mem-value').textContent = memPct.toFixed(1) + '%';
    $('mem-sub').textContent = s.mem ? (fmtBytes(s.mem.used) + ' / ' + fmtBytes(s.mem.total)) : '--';
    $('mem-bar').style.width = memPct.toFixed(1) + '%';

    var diskPct = (s.disk && s.disk.total > 0) ? (s.disk.used / s.disk.total * 100) : 0;
    $('disk-value').textContent = diskPct.toFixed(1) + '%';
    $('disk-sub').textContent = s.disk ? (fmtBytes(s.disk.used) + ' / ' + fmtBytes(s.disk.total)) : '--';
    $('disk-bar').style.width = diskPct.toFixed(1) + '%';

    updateGauges(cpu, memPct, diskPct, s);
  }

  /* ---------- 新鲜度 ---------- */
  function setFreshness(kind, text) {
    // SECURITY L4：textContent 渲染，杜绝 innerHTML 注入面
    var el = $('freshness');
    var pill = el.querySelector('.pill');
    if (!pill) {
      pill = document.createElement('span');
      pill.className = 'pill';
      el.appendChild(pill);
    }
    pill.className = 'pill ' + kind;
    pill.textContent = text;
  }
  function renderFreshness(l) {
    if (l.stale_sec === null || l.stale_sec === undefined) {
      setFreshness('pending', '等待数据');
    } else if (l.stale_sec <= 90) {
      setFreshness('ok', '正常');
    } else if (l.stale_sec <= 600) {
      setFreshness('warn', '延迟 ' + l.stale_sec + 's');
    } else {
      setFreshness('err', '延迟 ' + Math.round(l.stale_sec / 60) + 'min');
    }
  }

  /* ---------- 空数据提示 ---------- */
  function updateEmptyHint(s, l) {
    var el = $('empty-hint');
    var txt = $('empty-hint-text');
    if (!s || s.sample_count === 0) {
      el.hidden = false;
      txt.textContent = '正在等待首个采样点…（约一个采集间隔后出现数据，请稍候）';
    } else if (!l || !l.series || l.series.length === 0) {
      el.hidden = false;
      txt.textContent = '当前时间窗口内暂无速率样本，趋势图将随采样自动累积。';
    } else {
      el.hidden = true;
    }
  }

  /* ---------- ECharts ---------- */
  var rateChart = null, gaugeChart = null, monthlyChart = null;
  var gaugeText = { CPU: '--', 内存: '--', 磁盘: '--' };

  /* 三仪表响应式布局：按容器宽度推算半径，避免窄屏重叠 */
  function layoutGauges() {
    if (!gaugeChart) return;
    var el = $('chart-gauges');
    var w = el.clientWidth || 320;
    var h = el.clientHeight || 340;
    var halfMin = Math.min(w, h) / 2;
    if (halfMin <= 0) return;
    var maxR = (w * 0.76 / 3) / 2;
    var rp = Math.min((maxR / halfMin) * 100, 72);
    gaugeChart.setOption({
      series: [
        { center: ['22%', '56%'], radius: rp + '%' },
        { center: ['50%', '56%'], radius: rp + '%' },
        { center: ['78%', '56%'], radius: rp + '%' }
      ]
    });
  }

  /* ECharts 统一配色主题：cyan→violet 渐变系、弱化网格线、深色玻璃 tooltip */
  var ECHART = {
    cyan: '#22d3ee',
    cyanLight: '#67e8f9',
    cyanDeep: '#0891b2',
    purple: '#a78bfa',
    purpleLight: '#c4b5fd',
    purpleDeep: '#7c3aed',
    amber: '#fbbf24',
    text: '#e6edf7',
    dim: '#8290a6'
  };
  /* 纵向渐变辅助：折线填充 / 柱状渐变统一 */
  function gradArea(top, bottom) {
    return {
      type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
      colorStops: [
        { offset: 0, color: top },
        { offset: 1, color: bottom }
      ]
    };
  }
  var tooltipStyle = {
    backgroundColor: 'rgba(10, 16, 30, 0.88)',
    borderColor: 'rgba(255,255,255,0.10)',
    borderWidth: 1,
    textStyle: { color: ECHART.text, fontSize: 12 },
    extraCssText: 'border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.45),0 0 0 1px rgba(34,211,238,.05);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);'
  };
  var axisLabelStyle = { color: ECHART.dim, fontSize: 11 };
  var splitLineStyle = { lineStyle: { color: 'rgba(255,255,255,0.045)' } };
  var axisLineStyle = { lineStyle: { color: 'rgba(255,255,255,0.10)' } };

  function initCharts() {
    /* 实时速率折线图 */
    rateChart = echarts.init($('chart-rate'));
    rateChart.setOption({
      backgroundColor: 'transparent',
      animationDuration: 400,
      animationDurationUpdate: 300,
      aria: { enabled: true, description: '近 30 分钟实时网络速率折线图，包含入站与出站流量' },
      tooltip: Object.assign({
        trigger: 'axis',
        axisPointer: { type: 'line', lineStyle: { color: 'rgba(255,255,255,0.2)' } },
        formatter: function (params) {
          if (!params || !params.length) return '';
          var head = '<b>' + params[0].axisValue + '</b><br/>';
          var lines = params.map(function (p) {
            var v = p.value || 0;
            var f = fmtParts(v, RATE_UNITS);
            return p.marker + p.seriesName + '：<b>' + f.value + ' ' + f.unit + '</b>' +
              ' <span style="color:#8290a6">(' + (v * 8 / 1e6).toFixed(2) + ' Mbps)</span>';
          });
          return head + lines.join('<br/>');
        }
      }, tooltipStyle),
      legend: {
        top: 2, right: 6,
        icon: 'roundRect',
        itemWidth: 14, itemHeight: 6,
        textStyle: { color: '#8290a6', fontSize: 12 },
        data: ['入站', '出站']
      },
      grid: { left: 62, right: 20, top: 42, bottom: 30 },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: [],
        axisLine: axisLineStyle,
        axisTick: { show: false },
        axisLabel: Object.assign({}, axisLabelStyle, { formatter: function (v) { return v.slice(0, 5); } })
      },
      yAxis: {
        type: 'value',
        name: '',
        axisLabel: Object.assign({}, axisLabelStyle, { formatter: fmtRateAxis }),
        splitLine: splitLineStyle,
        axisLine: { show: false },
        nameTextStyle: { color: '#8290a6' }
      },
      series: [
        {
          name: '入站', type: 'line', smooth: 0.35, symbol: 'none',
          lineStyle: { width: 2.4, color: ECHART.cyan },
          itemStyle: { color: ECHART.cyan },
          emphasis: { focus: 'series' },
          areaStyle: {
            color: gradArea('rgba(34,211,238,0.32)', 'rgba(34,211,238,0.01)')
          },
          data: []
        },
        {
          name: '出站', type: 'line', smooth: 0.35, symbol: 'none',
          lineStyle: { width: 2.4, color: ECHART.purple },
          itemStyle: { color: ECHART.purple },
          emphasis: { focus: 'series' },
          areaStyle: {
            color: gradArea('rgba(167,139,250,0.28)', 'rgba(167,139,250,0.01)')
          },
          data: []
        }
      ]
    });

    /* CPU / 内存 / 磁盘 三仪表 */
    function mkGauge(name, color) {
      return {
        name: name,
        type: 'gauge',
        center: ['22%', '56%'],
        radius: '38%',
        startAngle: 225,
        endAngle: -45,
        min: 0, max: 100,
        splitNumber: 5,
        progress: {
          show: true, width: 11, roundCap: true,
          itemStyle: { color: color, shadowColor: color, shadowBlur: 8 }
        },
        axisLine: { lineStyle: { width: 11, color: [[1, 'rgba(255,255,255,0.06)']] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        pointer: { show: false },
        anchor: { show: false },
        title: {
          offsetCenter: [0, '38%'],
          color: ECHART.dim, fontSize: 12, fontWeight: 500
        },
        detail: {
          valueAnimation: true,
          offsetCenter: [0, '62%'],
          color: ECHART.text, fontSize: 13, fontWeight: 700,
          formatter: function () { return gaugeText[name] || '--'; }
        },
        data: [{ value: 0, name: name }]
      };
    }
    gaugeChart = echarts.init($('chart-gauges'));
    gaugeChart.setOption({
      backgroundColor: 'transparent',
      aria: { enabled: true, description: 'CPU、内存与磁盘使用率仪表盘' },
      series: [
        mkGauge('CPU', ECHART.cyan),
        mkGauge('内存', ECHART.purple),
        mkGauge('磁盘', ECHART.amber)
      ]
    });
    layoutGauges();

    /* 近 12 个月柱状图 */
    monthlyChart = echarts.init($('chart-monthly'));
    monthlyChart.setOption({
      backgroundColor: 'transparent',
      animationDuration: 600,
      animationDurationUpdate: 300,
      aria: { enabled: true, description: '近 12 个月入站与出站流量柱状图' },
      tooltip: Object.assign({
        trigger: 'axis',
        axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(255,255,255,0.04)' } },
        formatter: function (params) {
          if (!params || !params.length) return '';
          var idx = params[0].dataIndex;
          var month = monthlyMeta && monthlyMeta.months ? monthlyMeta.months[idx].month : '';
          var lines = params.map(function (p) {
            return p.marker + p.seriesName + '：<b>' + fmtBytes(p.value || 0) + '</b>';
          });
          return '<b>' + month + '</b><br/>' + lines.join('<br/>');
        }
      }, tooltipStyle),
      legend: {
        top: 2, right: 6,
        icon: 'roundRect',
        itemWidth: 14, itemHeight: 6,
        textStyle: { color: '#8290a6', fontSize: 12 },
        data: ['入站', '出站']
      },
      grid: { left: 64, right: 20, top: 42, bottom: 30 },
      xAxis: {
        type: 'category',
        data: [],
        axisLine: axisLineStyle,
        axisTick: { show: false },
        axisLabel: axisLabelStyle
      },
      yAxis: {
        type: 'value',
        axisLabel: Object.assign({}, axisLabelStyle, { formatter: fmtBytesAxis }),
        splitLine: splitLineStyle,
        axisLine: { show: false }
      },
      series: [
        {
          name: '入站', type: 'bar', barMaxWidth: 24,
          itemStyle: {
            borderRadius: [6, 6, 0, 0],
            color: gradArea(ECHART.cyanLight, ECHART.cyanDeep)
          },
          emphasis: { itemStyle: { shadowBlur: 12, shadowColor: 'rgba(34,211,238,0.35)' } },
          data: []
        },
        {
          name: '出站', type: 'bar', barMaxWidth: 24,
          itemStyle: {
            borderRadius: [6, 6, 0, 0],
            color: gradArea(ECHART.purpleLight, ECHART.purpleDeep)
          },
          emphasis: { itemStyle: { shadowBlur: 12, shadowColor: 'rgba(167,139,250,0.35)' } },
          data: []
        }
      ]
    });

    window.addEventListener('resize', function () {
      clearTimeout(window.__vpsmonResize);
      window.__vpsmonResize = setTimeout(function () {
        [rateChart, gaugeChart, monthlyChart].forEach(function (c) {
          if (c) c.resize();
        });
        layoutGauges();
      }, 150);
    });
  }

  var monthlyMeta = null;

  function renderMonthly(m) {
    monthlyMeta = m;
    var labels = m.months.map(function (x) { return x.month.slice(5) + '月'; });
    var rx = m.months.map(function (x) { return x.rx; });
    var tx = m.months.map(function (x) { return x.tx; });
    if (monthlyChart) {
      monthlyChart.setOption({
        xAxis: { data: labels },
        series: [{ data: rx }, { data: tx }]
      });
    }
    var cur = m.months[m.months.length - 1];
    if (cur) {
      $('month-rx').textContent = fmtBytes(cur.rx);
      $('month-tx').textContent = fmtBytes(cur.tx);
      $('month-rx-sub').textContent = cur.month + ' 累计 · 入站';
      $('month-tx-sub').textContent = cur.month + ' 累计 · 出站';
      $('monthly-badge').textContent = cur.month.slice(0, 4) + ' 年 · 近 12 个月';
    }
  }

  function loadMonthly() {
    apiGet('/traffic/monthly').then(renderMonthly).catch(function (e) {
      if (e && e.code === 'unauthorized') return;
      $('month-rx-sub').textContent = '月度数据加载失败';
      $('month-tx-sub').textContent = '月度数据加载失败';
    });
  }

  /* ---------- 实时数据渲染 ---------- */
  function renderLive(l) {
    $('rate-badge').textContent =
      '近 30 分钟 · 入站 ' + fmtRate(l.rx_rate || 0) + ' / 出站 ' + fmtRate(l.tx_rate || 0);
    renderFreshness(l);

    var times = [], rx = [], tx = [];
    (l.series || []).forEach(function (p) {
      times.push(fmtClock(p.ts));
      rx.push(p.rx_rate || 0);
      tx.push(p.tx_rate || 0);
    });
    if (rateChart) {
      rateChart.setOption({
        xAxis: { data: times },
        series: [{ data: rx }, { data: tx }]
      });
    }
  }

  function updateGauges(cpu, memPct, diskPct, s) {
    var memTxt = s.mem ? (fmtBytes(s.mem.used) + ' / ' + fmtBytes(s.mem.total)) : '--';
    var diskTxt = s.disk ? (fmtBytes(s.disk.used) + ' / ' + fmtBytes(s.disk.total)) : '--';
    gaugeText.CPU = cpu.toFixed(1) + '%';
    gaugeText.内存 = memTxt;
    gaugeText.磁盘 = diskTxt;
    if (gaugeChart) {
      gaugeChart.setOption({
        series: [
          { data: [{ value: cpu, name: 'CPU' }] },
          { data: [{ value: memPct, name: '内存' }] },
          { data: [{ value: diskPct, name: '磁盘' }] }
        ]
      });
    }
  }

  /* ---------- 轮询 ---------- */
  var pollingBusy = false;

  function refreshAll() {
    if (pollingBusy) return Promise.resolve();
    pollingBusy = true;
    return Promise.all([apiGet('/status'), apiGet('/traffic/live')])
      .then(function (res) {
        renderStatus(res[0]);
        renderLive(res[1]);
        updateEmptyHint(res[0], res[1]);
      })
      .catch(function (e) {
        if (e && e.code === 'unauthorized') return;
        setFreshness('err', '连接失败');
      })
      .then(function () {
        pollingBusy = false;
      });
  }

  /* ---------- 启动 ---------- */
  function boot() {
    $('host-addr').textContent = location.host;

    var ready = function () {
      try {
        initCharts();
      } catch (e) {
        console.error('ECharts 初始化失败', e);
        setFreshness('err', '图表初始化失败');
      }
      loadMonthly();
      refreshAll();
      setInterval(refreshAll, POLL_MS);
    };

    if (window.echarts) {
      ready();
    } else {
      // SECURITY M4：ECharts 已本地化（static/vendor/echarts.min.js 随包部署），
      // 不再加载任何外部 CDN 脚本——消除第三方脚本执行面，且使 CSP
      // script-src 'self' 严格成立。vendor 缺失时明确报错而非远程兜底。
      setFreshness('err', '图表库加载失败');
      $('empty-hint').hidden = false;
      $('empty-hint-text').textContent = '图表库（ECharts）未随包部署，请确认 static/vendor/echarts.min.js 存在后刷新。';
      loadMonthly();
      refreshAll();
      setInterval(refreshAll, POLL_MS);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
