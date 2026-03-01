/**
 * data.js — источник данных каталога
 *
 * Игры хранятся в БД на Railway API.
 * fetchGames() запрашивает их через GET /api/games.
 *
 * source: 'local' | 'steam'
 *   local = мгновенно из локальной базы (⚡)
 *   steam = через Steampass — База данных (🔵)
 */

const steamImg = id =>
  `https://cdn.cloudflare.steamstatic.com/steam/apps/${id}/header.jpg`;

async function fetchGames() {
  // Берём URL из auth_config.js (THEPASS_API_URL) или AUTH_CONFIG.BASE_URL
  // data.js грузится раньше auth_config.js, поэтому читаем в момент вызова
  const apiBase =
    (typeof THEPASS_API_URL !== 'undefined' && THEPASS_API_URL)
      ? THEPASS_API_URL
      : (typeof AUTH_CONFIG !== 'undefined' && AUTH_CONFIG.BASE_URL)
        ? AUTH_CONFIG.BASE_URL
        : 'https://thepass-api.up.railway.app';

  try {
    const res = await fetch(`${apiBase}/api/games`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const games = await res.json();
    return games.map(g => ({
      ...g,
      img: steamImg(g.steamId),
    }));
  } catch (e) {
    console.error('[fetchGames] Не удалось загрузить игры с API:', e);
    return [];
  }
}
