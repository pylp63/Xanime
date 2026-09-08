// ─── Nav auth state (runs on every page with a #nav-auth container) ──────────
(function initNavAuth() {
  const nav = document.getElementById('nav-auth');
  if (!nav) return;

  fetch('/api/me', { credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (me) {
      if (!me || !me.username) return;
      nav.innerHTML =
        '<span class="text-text-muted text-sm px-1">' + me.username + '</span>' +
        '<a href="/settings/" class="btn-glass text-sm">设置</a>' +
        '<button id="logout-btn" class="btn-glass text-sm">退出</button>';
      const lb = document.getElementById('logout-btn');
      if (lb) lb.addEventListener('click', function (e) {
        e.preventDefault();
        fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
          .then(function () { window.location.href = '/login'; });
      });
    })
    .catch(function () {});
})();

// SPA client-side router for detail/watch pages
const path = window.location.pathname;
const app = document.getElementById('app');

if (app) {
  const detailMatch = path.match(/^\/xanime\/(\d+)\/?$/);
  const watchMatch = path.match(/^\/watch\/(\d+)\/(\d+)\/?$/);

  if (detailMatch) {
    renderDetail(Number(detailMatch[1]));
  } else if (watchMatch) {
    renderWatch(Number(watchMatch[1]), Number(watchMatch[2]));
  }
}

function getCoverUrl(cover) {
  if (!cover || !cover.trim() === '') {
    return 'https://via.placeholder.com/480x640/141428/8b5cf6?text=Xanime';
  }
  if (cover.startsWith('http')) return cover;
  if (cover.startsWith('/')) return cover;
  return '/static/' + cover;
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

async function presignURL(key) {
  try {
    const data = await fetchJSON('/api/files/presign?key=' + encodeURIComponent(key));
    return (data && data.url) || '';
  } catch (e) { return ''; }
}

async function renderDetail(id) {
  const xanime = await fetchJSON('/api/xanimes/' + id);
  const episodes = await fetchJSON('/api/xanimes/' + id + '/episodes');

  if (!xanime) {
    app.innerHTML = '<div class="text-center py-20"><p class="text-text-muted text-lg">影片未找到</p><a href="/" class="text-primary-light mt-4 inline-block">返回首页</a></div>';
    return;
  }

  var eps = (episodes || []).map(function(ep) {
    return '<a href="/watch/' + xanime.id + '/' + ep.number + '/" class="episode-btn text-center py-2 text-sm font-medium">' + ep.number + '</a>';
  }).join('');

  app.innerHTML =
    '<main class="max-w-7xl mx-auto px-4 py-6 animate-fade-in">' +
      '<div class="flex flex-col md:flex-row gap-8 mb-10">' +
        '<div class="w-48 shrink-0"><img src="' + getCoverUrl(xanime.cover) + '" alt="' + xanime.title + '" class="w-full rounded-2xl shadow-2xl border border-white/10" /></div>' +
        '<div class="glass rounded-3xl p-6 flex-1">' +
          '<h1 class="text-2xl md:text-3xl font-bold mb-3">' + xanime.title + '</h1>' +
          '<div class="flex flex-wrap items-center gap-3 text-sm mb-4">' +
            (xanime.rating > 0 ? '<span class="text-yellow-300 font-bold">★ ' + xanime.rating.toFixed(1) + '</span>' : '') +
            '<span class="text-text-muted">' + xanime.year + '</span>' +
            '<span class="glass-chip-accent px-2 py-0.5 rounded-lg text-xs">' + xanime.category + '</span>' +
            '<span class="text-text-muted">' + xanime.episodes + ' 话</span>' +
          '</div>' +
          '<p class="text-text-muted text-sm leading-relaxed whitespace-pre-line">' + xanime.description + '</p>' +
        '</div>' +
      '</div>' +
      '<h2 class="text-xl font-bold mb-4">剧集列表</h2>' +
      '<div class="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-2.5">' + (eps || '<p class="text-text-muted text-sm">暂无剧集</p>') + '</div>' +
    '</main>';
}

async function renderWatch(xanimeId, epNumber) {
  var xanime = await fetchJSON('/api/xanimes/' + xanimeId);
  var episodes = await fetchJSON('/api/xanimes/' + xanimeId + '/episodes');

  if (!xanime) {
    app.innerHTML = '<div class="text-center py-20"><p class="text-text-muted">加载中…</p></div>';
    return;
  }

  var eps = episodes || [];
  var current = null, prevEp = null, nextEp = null;
  for (var i = 0; i < eps.length; i++) {
    if (eps[i].number === epNumber) current = eps[i];
    if (eps[i].number === epNumber - 1) prevEp = eps[i];
    if (eps[i].number === epNumber + 1) nextEp = eps[i];
  }

  // Get presigned URL from backend (works for local, NFS and S3 sources)
  var videoSrc = '';
  if (current) {
    videoSrc = await presignURL(current.video_url);
  }

  var epGrid = eps.map(function(ep) {
    var cls = ep.number === epNumber ? 'episode-btn active text-center py-2 text-sm font-medium' : 'episode-btn text-center py-2 text-sm font-medium';
    return '<a href="/watch/' + xanime.id + '/' + ep.number + '/" class="' + cls + '">' + ep.number + '</a>';
  }).join('');

  app.innerHTML =
    '<main class="max-w-6xl mx-auto px-4 py-6 animate-fade-in">' +
      '<div class="video-container shadow-2xl mb-6">' +
        (videoSrc ? '<video controls autoplay class="w-full h-full"><source src="' + videoSrc + '" type="video/mp4" /></video>' : '<div class="flex items-center justify-center h-full text-text-muted">暂无视频源</div>') +
      '</div>' +
      '<div class="glass rounded-3xl p-5 flex items-center justify-between mb-6"><div>' +
        '<h1 class="text-lg md:text-xl font-bold">' + xanime.title + ' - 第 ' + epNumber + ' 话</h1>' +
        (current ? '<p class="text-text-muted text-sm mt-0.5">' + current.title + '</p>' : '') +
      '</div><div class="flex gap-2">' +
        (prevEp ? '<a href="/watch/' + xanime.id + '/' + prevEp.number + '/" class="btn-glass text-sm">← 上一话</a>' : '<span class="btn-glass text-sm opacity-40 cursor-default">← 上一话</span>') +
        (nextEp ? '<a href="/watch/' + xanime.id + '/' + nextEp.number + '/" class="btn-glass text-sm">下一话 →</a>' : '<span class="btn-glass text-sm opacity-40 cursor-default">下一话 →</span>') +
      '</div></div>' +
      '<h2 class="font-bold mb-3">剧集列表</h2>' +
      '<div class="grid grid-cols-5 sm:grid-cols-6 md:grid-cols-8 lg:grid-cols-10 gap-2.5">' + epGrid + '</div>' +
    '</main>';
}
