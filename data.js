/**
 * data.js — источник данных каталога
 *
 * Игры хранятся в БД на Railway API.
 * Этот файл просто запрашивает их оттуда.
 *
 * source: 'local' | 'steam'
 *   local = мгновенно из локальной базы (⚡)
 *   steam = через Steampass — База данных (🔵)
 */

const steamImg = id =>
  `https://cdn.cloudflare.steamstatic.com/steam/apps/${id}/header.jpg`;

const _API_BASE = (typeof AUTH_CONFIG !== 'undefined' && AUTH_CONFIG.BASE_URL)
  ? AUTH_CONFIG.BASE_URL
  : 'https://thepass-api.up.railway.app';

async function fetchGames() {
  try {
    const res = await fetch(`${_API_BASE}/api/games`);
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
