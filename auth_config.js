/**
 * auth_config.js — конфигурация API для системы аккаунтов The Pass
 *
 * ⚠️ ВАЖНО: Этот файл нужно подключить в index.html ПЕРЕД auth.js
 *
 * Поскольку сайт хостится на GitHub Pages, а API (api.py) запущен
 * отдельно — укажи здесь полный адрес своего сервера.
 *
 * Варианты:
 *   - Локальная разработка:     'http://localhost:8000'
 *   - Railway/Render (прод):    'https://your-app.railway.app'
 *   - VPS с доменом:            'https://api.thepass.ru'
 *
 * Если API ещё не задеплоен — оставь пустую строку '',
 * тогда кнопки аккаунта будут скрыты автоматически.
 */

const THEPASS_API_URL = 'https://thepass-api.up.railway.app';
// Замени на реальный адрес своего сервера ↑
// Пример: 'https://thepass-api.railway.app'
// Пример: 'http://localhost:8000'  (для теста локально)
