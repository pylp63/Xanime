// ─── Nav auth state (runs on every page with a #nav-auth container) ──────────
(function initNavAuth() {
  const nav = document.getElementById('nav-auth');
  if (!nav) return;

  nav.addEventListener('click', function (e) {
    var logoutBtn = e.target.closest('#logout-btn');
    if (logoutBtn) {
      e.preventDefault();
      fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
        .then(function () { window.location.href = '/login'; });
    }
  });

  fetch('/api/me', { credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (me) {
      if (!me || !me.username) return;
      var isAdmin = me.role === 'admin';
      nav.innerHTML =
        '<span class="text-text-muted text-sm px-1">' + me.username + (isAdmin ? '' : '') + '</span>' +
        (isAdmin
          ? '<a href="/settings/" class="btn-glass text-sm">设置</a>'
          : '<a href="/password/" class="btn-glass text-sm">修改密码</a>') +
        '<button id="logout-btn" class="btn-glass text-sm">退出</button>';
    })
    .catch(function () {});
})();

// SPA client-side router for detail/watch pages
// Routes: /xanime/<srcID>/<name>/  and  /watch/<srcID>/<name>/<file>/
const path = window.location.pathname;
const app = document.getElementById('app');

if (app) {
  const detailMatch = path.match(/^\/xanime\/([^/]+)\/(.+)\/?$/);
  const watchMatch = path.match(/^\/watch\/([^/]+)\/(.+)\/([^/]+)\/?$/);

  if (detailMatch) {
    withTransition(function () {
      return renderDetail(decodeURIComponent(detailMatch[1]), decodeURIComponent(detailMatch[2]));
    });
  } else if (watchMatch) {
    withTransition(function () {
      return renderWatch(decodeURIComponent(watchMatch[1]), decodeURIComponent(watchMatch[2]), decodeURIComponent(watchMatch[3]));
    });
  }
}

// 页面切换过渡: 旧内容缩小远去 → 替换内容 → 新内容放大进入 (鸿蒙风格)
function withTransition(renderFn) {
  var main = document.querySelector('#app main');
  if (!main || typeof main.animate !== 'function') { renderFn(); return; }

  // exit 动画与内容渲染并行: 一边播放退出动画, 一边在后台 fetch+渲染新内容,
  // 避免"退出动画播完 → 等 fetch → 再进入动画"的串行停顿。
  var exitAnim = main.animate(
    [
      { opacity: 1, transform: 'scale(1)' },
      { opacity: 0, transform: 'scale(0.96)' }
    ],
    { duration: 190, easing: 'cubic-bezier(0.4, 0, 0.2, 1)' }
  );

  Promise.all([
    new Promise(function (res) { exitAnim.onfinish = res; }),
    Promise.resolve(renderFn())
  ]).then(function () {
    var fresh = document.querySelector('#app main');
    if (!fresh) return;
    // enter: 由远到近 (纯 transform+opacity, GPU 合成, 结束后清理 willChange)
    fresh.style.opacity = '0';
    fresh.style.willChange = 'transform, opacity';
    var enterAnim = fresh.animate(
      [
        { opacity: 0, transform: 'scale(1.04)' },
        { opacity: 1, transform: 'scale(1)' }
      ],
      { duration: 240, easing: 'cubic-bezier(0.22, 1, 0.36, 1)' }
    );
    enterAnim.onfinish = function () { fresh.style.willChange = 'auto'; fresh.style.opacity = ''; };

    // 剧集网格错峰进入
    var grids = fresh.querySelectorAll('.grid');
    grids.forEach(function (g) {
      Array.from(g.children).forEach(function (child, i) {
        child.animate(
          [
            { opacity: 0, transform: 'translateY(10px)' },
            { opacity: 1, transform: 'translateY(0)' }
          ],
          { duration: 240, delay: Math.min(i * 18, 260), easing: 'cubic-bezier(0.22, 1, 0.36, 1)' }
        );
      });
    });
  });
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

async function fetchJSON(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (res.status === 401) {
    window.location.href = '/login';
    return null;
  }
  if (!res.ok) return null;
  return res.json();
}

// library 数据缓存: 首页/详情/播放页共享同一份目录扫描结果,
// 避免每次 SPA 切换都重新全量扫描 (scanSourceDir 是实时遍历文件的)。
var libraryCache = { promise: null, at: 0 };
var LIBRARY_TTL = 2000; // 2s 内复用, 足够一次浏览会话内的连续切换
function getLibrary() {
  var now = Date.now();
  if (libraryCache.promise && (now - libraryCache.at) < LIBRARY_TTL) {
    return libraryCache.promise;
  }
  libraryCache.at = now;
  libraryCache.promise = fetchJSON('/api/library');
  return libraryCache.promise;
}

async function presignURL(key) {
  try {
    const data = await fetchJSON('/api/files/presign?key=' + encodeURIComponent(key));
    return (data && data.url) || '';
  } catch (e) { return ''; }
}

function fmtSize(bytes) {
  if (!bytes) return '';
  var units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return bytes.toFixed(bytes >= 100 || i === 0 ? 0 : 1) + ' ' + units[i];
}

async function renderDetail(srcID, name) {
  // Library detail: episodes come from real files in the anime directory.
  // 并行请求 episodes + library(带缓存), 不再串行等待两次网络往返。
  const [eps, lib] = await Promise.all([
    fetchJSON('/api/library/' + encodeURIComponent(srcID) + '/' + encodeURIComponent(name) + '/episodes'),
    getLibrary()
  ]);
  const meta = lib && (lib.data || []).find(function (a) { return a.name === name && a.source_id === srcID; });
  const title = (meta && meta.title) || name.split('/').pop();

  if (!eps) {
    app.innerHTML = '<div class="text-center py-20"><p class="text-text-muted text-lg">未找到该动漫目录</p><a href="/" class="brand-text mt-4 inline-block">返回首页</a></div>';
    return;
  }

  var epList = (eps || []).map(function (ep, i) {
    return '<a href="/watch/' + encodeURIComponent(srcID) + '/' + encodeURIComponent(name) + '/' + encodeURIComponent(ep.file) + '/" class="episode-btn px-3 py-2.5 text-sm font-medium text-center truncate" title="' + esc(ep.file) + '">' +
      esc(ep.name) + '</a>';
  }).join('');

  var cover = meta && meta.cover
    ? meta.cover
    : 'https://via.placeholder.com/480x640/dbeafe/0a6fd8?text=' + encodeURIComponent(name.slice(0, 6));

  app.innerHTML =
    '<main class="max-w-7xl mx-auto px-4 py-6 animate-fade-in">' +
      '<div class="flex flex-col md:flex-row gap-8 mb-10">' +
        '<div class="w-48 shrink-0"><img src="' + esc(cover) + '" alt="' + esc(name) + '" class="w-full rounded-2xl shadow-2xl border border-white/10" /></div>' +
        '<div class="glass rounded-3xl p-6 flex-1">' +
          '<h1 class="text-2xl md:text-3xl font-bold mb-3">' + esc(title) + '</h1>' +
          '<div class="flex flex-wrap items-center gap-3 text-sm mb-4">' +
            '<span class="text-text-muted">' + (eps ? eps.length : 0) + ' 集</span>' +
            (meta && meta.year ? '<span class="tag-chip">' + meta.year + '</span>' : '') +
            (meta && meta.source_name ? '<span class="tag-chip">' + esc(meta.source_name) + '</span>' : '') +
          '</div>' +
          '<p class="text-text-muted text-sm">剧集来自目录中的真实视频文件，按文件名自然排序。</p>' +
        '</div>' +
      '</div>' +
      '<h2 class="text-xl font-bold mb-4">剧集列表</h2>' +
      '<div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2.5">' + (epList || '<p class="text-text-muted text-sm">该目录下没有视频文件</p>') + '</div>' +
    '</main>';
}

async function renderWatch(srcID, name, file) {
  const [eps, lib] = await Promise.all([
    fetchJSON('/api/library/' + encodeURIComponent(srcID) + '/' + encodeURIComponent(name) + '/episodes'),
    getLibrary()
  ]);
  const meta = lib && (lib.data || []).find(function (a) { return a.name === name && a.source_id === srcID; });
  const title = (meta && meta.title) || name.split('/').pop();

  if (!eps || !eps.length) {
    app.innerHTML = '<div class="text-center py-20"><p class="text-text-muted">未找到该动漫目录</p></div>';
    return;
  }

  var list = eps || [];
  var current = null, prevEp = null, nextEp = null;
  for (var i = 0; i < list.length; i++) {
    if (list[i].file === file) { current = list[i]; }
  }
  var idx = list.indexOf(current);
  if (idx > 0) prevEp = list[idx - 1];
  if (idx >= 0 && idx < list.length - 1) nextEp = list[idx + 1];
  if (!current && list.length) { current = list[0]; idx = 0; }

  // Resolve the playable URL through presign (works for local/NFS/S3)
  var videoSrc = '';
  if (current) {
    videoSrc = await presignURL(current.path);
  }

  var epGrid = list.map(function (ep) {
    var cls = ep.file === file ? 'episode-btn active' : 'episode-btn';
    return '<a href="/watch/' + encodeURIComponent(srcID) + '/' + encodeURIComponent(name) + '/' + encodeURIComponent(ep.file) + '/" class="' + cls + ' px-2.5 py-2 text-xs font-medium text-center truncate" title="' + esc(ep.file) + '">' + esc(ep.name) + '</a>';
  }).join('');

  var currentTitle = current ? current.name : file;

  app.innerHTML =
    '<main class="max-w-6xl mx-auto px-4 py-6 animate-fade-in">' +
      '<div class="video-container shadow-2xl mb-6">' +
        (videoSrc ? '<video controls autoplay class="w-full h-full"><source src="' + videoSrc + '" /></video>' : '<div class="flex items-center justify-center h-full text-text-muted">暂无视频源</div>') +
      '</div>' +
      '<div class="glass rounded-3xl p-5 flex flex-wrap items-center justify-between gap-3 mb-6"><div class="min-w-0">' +
        '<h1 class="text-lg md:text-xl font-bold truncate">' + esc(title) + ' · ' + esc(currentTitle) + '</h1>' +
        (current && current.size ? '<p class="text-text-muted text-xs mt-0.5">' + fmtSize(current.size) + ' · ' + esc(current.file) + '</p>' : '') +
      '</div><div class="flex gap-2">' +
        (prevEp ? '<a href="/watch/' + encodeURIComponent(srcID) + '/' + encodeURIComponent(name) + '/' + encodeURIComponent(prevEp.file) + '/" class="btn-glass text-sm">← ' + esc(prevEp.name) + '</a>' : '<span class="btn-glass text-sm opacity-40 cursor-default">← 上一集</span>') +
        (nextEp ? '<a href="/watch/' + encodeURIComponent(srcID) + '/' + encodeURIComponent(name) + '/' + encodeURIComponent(nextEp.file) + '/" class="btn-glass text-sm">' + esc(nextEp.name) + ' →</a>' : '<span class="btn-glass text-sm opacity-40 cursor-default">下一集 →</span>') +
      '</div></div>' +
      '<h2 class="font-bold mb-3">剧集列表</h2>' +
      '<div class="grid grid-cols-3 sm:grid-cols-5 md:grid-cols-7 lg:grid-cols-9 gap-2.5">' + epGrid + '</div>' +
    '</main>';
}
