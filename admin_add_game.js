/**
 * admin_add_game.js — модуль добавления игры (только для admin)
 *
 * Подключить в index.html ПОСЛЕ auth.js и admin_panel.js:
 *   <script src="admin_add_game.js"></script>
 *
 * Открытие: AdminAddGame.open()
 *
 * Логика:
 *   1. Форма заполняется в красивой модалке
 *   2. POST /api/admin/games/add → API дописывает запись в data.js на сервере
 *   3. Страница перезагружает fetchGames() без reload
 *
 * Поля:
 *   title        — название игры (обязательно)
 *   short        — короткое название / аббревиатура
 *   group        — студия / группа (выпадающий + произвольный ввод)
 *   hasDlc       — есть ли DLC (toggle)
 *   source       — 'local' (Marme1adker) | 'steam' (база данных) | 'marme1adker' (только аккаунт)
 *   marme1adker  — доступна в аккаунте Marme1adker
 *   steamId      — AppID из Steam Store (для обложки)
 *   steampassUrl — ссылка на steampass (если source != local)
 *   tags         — теги через запятую
 *   opts         — dlc, ru, online (чекбоксы)
 */

const AdminAddGame = (() => {

  // ── Известные студии из data.js ───────────────────────────────
  const KNOWN_STUDIOS = [
    'Rockstar', 'CD Projekt Red', 'Ubisoft', 'Valve', 'FromSoftware',
    'PlayStation', 'Gearbox', 'Bethesda', '2K', 'Paradox', 'EA',
    'Activision', 'Microsoft', 'Kunos', 'SCS Software', 'Codemasters',
    'Focus', 'Larian Studios', 'Hello Games', 'Mundfish', 'Remedy',
    'Metro series', 'Hitman series', 'Hotline Miami', 'Batman Arkham',
    'Resident Evil', 'BioShock', 'Wolfenstein', 'The Dark Pictures',
    'Choice of Life', 'LEGO', 'FlatOut', 'Alan Wake',
    'Инди • Выживание', 'Инди • Хоррор', 'Инди • Roguelike',
    'Инди • Платформер', 'Инди • RPG', 'Инди • Кооп',
    'Инди • Симулятор', 'Инди • Стратегия', 'Инди • Экшн',
    'Инди • Разное',
  ];

  // ── Состояние ─────────────────────────────────────────────────
  let _overlay  = null;
  let _editGame = null;  // объект игры при редактировании, null при добавлении

  // ── Helpers ───────────────────────────────────────────────────
  function _getApiBase() {
    if (typeof THEPASS_API_URL !== 'undefined' && THEPASS_API_URL) return THEPASS_API_URL;
    if (typeof AUTH_CONFIG !== 'undefined' && AUTH_CONFIG.BASE_URL) return AUTH_CONFIG.BASE_URL;
    return '';
  }

  function _getToken() {
    if (typeof Auth !== 'undefined' && Auth.token) return Auth.token;
    return sessionStorage.getItem('thepass_token') || localStorage.getItem('thepass_token') || '';
  }

  function _escHtml(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  // ── Создать HTML модалки ──────────────────────────────────────
  function _buildHTML(editMode = false) {
    const studioOptions = KNOWN_STUDIOS.map(s =>
      `<option value="${_escHtml(s)}">${_escHtml(s)}</option>`
    ).join('');

    return `
<div class="aga-overlay" id="agaOverlay">
  <div class="aga-modal" id="agaModal">
    <div class="aga-header">
      <div class="aga-header-left">
        <div class="aga-icon">${editMode ? '✏️' : '🎮'}</div>
        <div>
          <div class="aga-title">${editMode ? 'Редактировать игру' : 'Добавить игру'}</div>
          <div class="aga-subtitle">${editMode ? 'Изменить данные игры' : 'Новая запись в каталог'}</div>
        </div>
      </div>
      <button class="aga-close" id="agaClose">✕</button>
    </div>

    <div class="aga-body">

      <!-- Превью обложки -->
      <div class="aga-preview" id="agaPreview">
        <div class="aga-preview-placeholder" id="agaPreviewPlaceholder">
          <span>🎮</span>
          <span>Введите Steam ID для превью</span>
        </div>
        <img class="aga-preview-img" id="agaPreviewImg" src="" alt="" style="display:none">
        <div class="aga-preview-overlay" id="agaPreviewOverlay" style="display:none">
          <div class="aga-preview-title" id="agaPreviewTitle"></div>
        </div>
      </div>

      <!-- Форма -->
      <div class="aga-form">

        <!-- БЛОК 1: Основное -->
        <div class="aga-section-label">Основное</div>

        <div class="aga-field">
          <label class="aga-label">Название игры <span class="aga-req">*</span></label>
          <input class="aga-input" id="agaTitle" type="text" placeholder="Например: Hollow Knight" autocomplete="off">
          <div class="aga-field-hint">Полное официальное название</div>
        </div>

        <div class="aga-row2">
          <div class="aga-field">
            <label class="aga-label">Короткое название</label>
            <input class="aga-input" id="agaShort" type="text" placeholder="HK, GTA V, RDR2..." autocomplete="off">
            <div class="aga-field-hint">Аббревиатура / краткое</div>
          </div>
          <div class="aga-field">
            <label class="aga-label">Steam AppID <span class="aga-req">*</span></label>
            <input class="aga-input" id="agaSteamId" type="text" inputmode="numeric" placeholder="367520" autocomplete="off">
            <div class="aga-field-hint">Для обложки / ссылки</div>
          </div>
        </div>

        <!-- БЛОК 2: Студия -->
        <div class="aga-section-label">Студия</div>

        <div class="aga-field">
          <label class="aga-label">Студия / группа <span class="aga-req">*</span></label>
          <div class="aga-studio-wrap">
            <select class="aga-select" id="agaStudioSelect">
              <option value="">— Выбрать из списка —</option>
              ${studioOptions}
              <option value="__custom__">✏️ Ввести свою...</option>
            </select>
            <input class="aga-input" id="agaStudioCustom" type="text"
              placeholder="Название студии (незнакомая → Инди • Разное)"
              style="display:none" autocomplete="off">
          </div>
          <div class="aga-field-hint" id="agaStudioHint">Если студии нет в списке — выберите «Ввести свою» или оставьте «Инди • Разное»</div>
        </div>

        <!-- БЛОК 3: Источник -->
        <div class="aga-section-label">Источник данных</div>

        <div class="aga-source-grid">
          <button class="aga-source-btn" data-source="local" id="agaSrcLocal">
            <div class="aga-source-icon">⚡</div>
            <div class="aga-source-name">Локальная</div>
            <div class="aga-source-desc">Marme1adker база</div>
          </button>
          <button class="aga-source-btn" data-source="steam" id="agaSrcSteam">
            <div class="aga-source-icon">🔵</div>
            <div class="aga-source-name">База данных</div>
            <div class="aga-source-desc">Через Steampass</div>
          </button>
        </div>

        <!-- Marme1adker toggle -->
        <div class="aga-toggle-row" id="agaMarmeRow">
          <div>
            <div class="aga-toggle-label">Доступна в аккаунте Marme1adker</div>
            <div class="aga-toggle-hint">Игра есть на аккаунте marme1adker</div>
          </div>
          <button class="aga-toggle" id="agaMarmeToggle" data-on="false" aria-label="Marme1adker">
            <span class="aga-toggle-knob"></span>
          </button>
        </div>

        <!-- Steampass URL (только для steam source) -->
        <div class="aga-field" id="agaSteampassRow" style="display:none">
          <label class="aga-label">Ссылка на Steampass</label>
          <input class="aga-input" id="agaSteampassUrl" type="url"
            placeholder="https://steampass.ru/game/..." autocomplete="off">
          <div class="aga-field-hint">Страница игры на steampass.ru</div>
        </div>

        <!-- БЛОК 4: Теги и опции -->
        <div class="aga-section-label">Теги и опции</div>

        <div class="aga-field">
          <label class="aga-label">Теги</label>
          <input class="aga-input" id="agaTags" type="text"
            placeholder="RPG, Открытый мир, Сюжет, Кооп" autocomplete="off">
          <div class="aga-field-hint">Через запятую. Будут добавлены в фильтры.</div>
        </div>

        <!-- Популярные теги -->
        <div class="aga-quick-tags" id="agaQuickTags"></div>

        <div class="aga-opts-row">
          <label class="aga-opt-chip" id="agaOptDlc">
            <input type="checkbox" id="agaChkDlc"> <span>🔖 DLC</span>
          </label>
          <label class="aga-opt-chip" id="agaOptRu">
            <input type="checkbox" id="agaChkRu"> <span>🇷🇺 Русский</span>
          </label>
          <label class="aga-opt-chip" id="agaOptOnline">
            <input type="checkbox" id="agaChkOnline"> <span>🌐 Онлайн</span>
          </label>
        </div>

        <!-- DLC toggle (крупный) -->
        <div class="aga-toggle-row">
          <div>
            <div class="aga-toggle-label">Есть DLC / дополнения</div>
            <div class="aga-toggle-hint">Игра имеет платный контент / сезонный пропуск</div>
          </div>
          <button class="aga-toggle" id="agaDlcToggle" data-on="false" aria-label="DLC">
            <span class="aga-toggle-knob"></span>
          </button>
        </div>

      </div><!-- /aga-form -->
    </div><!-- /aga-body -->

    <!-- Футер -->
    <div class="aga-footer">
      <div class="aga-status" id="agaStatus"></div>
      <div class="aga-footer-btns">
        <button class="aga-btn aga-btn-cancel" id="agaCancel">Отмена</button>
        <button class="aga-btn aga-btn-submit" id="agaSubmit">
          <span id="agaSubmitText">${editMode ? 'Сохранить изменения' : 'Добавить в каталог'}</span>
          <span class="aga-spinner" id="agaSpinner" style="display:none"></span>
        </button>
      </div>
    </div>

  </div><!-- /aga-modal -->
</div><!-- /aga-overlay -->
`;
  }

  // ── Стили ─────────────────────────────────────────────────────
  function _injectStyles() {
    if (document.getElementById('aga-styles')) return;
    const style = document.createElement('style');
    style.id = 'aga-styles';
    style.textContent = `
/* ── AdminAddGame Overlay ─────────────────────────────── */
.aga-overlay {
  position: fixed; inset: 0; z-index: 9999;
  background: rgba(5, 4, 12, 0.88);
  backdrop-filter: blur(12px);
  display: flex; align-items: flex-end; justify-content: center;
  opacity: 0; transition: opacity .25s;
  pointer-events: none;
  overflow: hidden;
}
.aga-overlay.open {
  opacity: 1; pointer-events: all;
}
.aga-modal {
  width: 100%; max-width: 520px;
  background: var(--surface, #14111f);
  border: 1px solid var(--border, #2a2540);
  border-radius: 24px 24px 0 0;
  display: flex; flex-direction: column;
  max-height: 92dvh;
  transform: translateY(100%);
  transition: transform .3s cubic-bezier(.32,.72,0,1);
  overflow: hidden;
}
.aga-overlay.open .aga-modal {
  transform: translateY(0);
}

/* Header */
.aga-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 18px 18px 14px;
  border-bottom: 1px solid var(--border, #2a2540);
  flex-shrink: 0;
}
.aga-header-left { display: flex; align-items: center; gap: 12px; }
.aga-icon {
  width: 42px; height: 42px; border-radius: 12px;
  background: linear-gradient(135deg, #8b5cf6, #6d28d9);
  display: flex; align-items: center; justify-content: center; font-size: 20px;
  box-shadow: 0 4px 16px rgba(139,92,246,.35);
  flex-shrink: 0;
}
.aga-title {
  font-family: 'Syne', sans-serif; font-size: 17px; font-weight: 800;
  color: var(--text, #f0eeff);
}
.aga-subtitle { font-size: 11px; color: var(--muted, #7a6fa0); margin-top: 2px; }
.aga-close {
  width: 34px; height: 34px; border-radius: 10px;
  background: var(--surface2, #1c1830); border: 1px solid var(--border, #2a2540);
  color: var(--muted, #7a6fa0); font-size: 14px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  transition: all .15s;
}
.aga-close:hover { border-color: var(--purple, #8b5cf6); color: var(--text, #f0eeff); }

/* Body scroll */
.aga-body { overflow-y: auto; flex: 1; min-height: 0; padding: 16px; }

/* Preview */
.aga-preview {
  position: relative; height: 120px; border-radius: 14px; overflow: hidden;
  margin-bottom: 16px; background: var(--surface2, #1c1830);
  border: 1px solid var(--border, #2a2540);
  transition: border-color .2s;
}
.aga-preview.has-img { border-color: rgba(139,92,246,.4); }
.aga-preview-placeholder {
  position: absolute; inset: 0; display: flex;
  flex-direction: column; align-items: center; justify-content: center;
  gap: 6px; color: var(--dim, #4a4460); font-size: 13px;
}
.aga-preview-placeholder span:first-child { font-size: 28px; }
.aga-preview-img {
  width: 100%; height: 100%; object-fit: cover;
  transition: opacity .3s;
}
.aga-preview-overlay {
  position: absolute; inset: 0;
  background: linear-gradient(to top, rgba(5,4,12,.9) 0%, transparent 60%);
  display: flex; align-items: flex-end; padding: 10px 14px;
}
.aga-preview-title {
  font-family: 'Syne', sans-serif; font-size: 15px; font-weight: 800;
  color: #fff; text-shadow: 0 2px 8px rgba(0,0,0,.8);
}

/* Section label */
.aga-section-label {
  font-family: 'Syne', sans-serif; font-size: 10px; font-weight: 700;
  color: var(--accent, #a78bfa); text-transform: uppercase; letter-spacing: .8px;
  margin: 18px 0 10px;
}
.aga-section-label:first-child { margin-top: 0; }

/* Fields */
.aga-field { margin-bottom: 12px; }
.aga-label {
  display: block; font-family: 'Syne', sans-serif; font-size: 11px; font-weight: 700;
  color: var(--text, #f0eeff); margin-bottom: 6px; text-transform: uppercase; letter-spacing: .4px;
}
.aga-req { color: #f87171; }
.aga-input, .aga-select {
  width: 100%; box-sizing: border-box; padding: 11px 14px;
  background: var(--surface2, #1c1830); border: 1.5px solid var(--border, #2a2540);
  border-radius: 12px; color: var(--text, #f0eeff);
  font-family: 'Inter', sans-serif; font-size: 13px;
  transition: border-color .15s, box-shadow .15s;
  outline: none; appearance: none;
}
.aga-input:focus, .aga-select:focus {
  border-color: var(--purple, #8b5cf6);
  box-shadow: 0 0 0 3px rgba(139,92,246,.12);
}
.aga-input::placeholder { color: var(--dim, #4a4460); }
.aga-input.error { border-color: #f87171; box-shadow: 0 0 0 3px rgba(248,113,113,.1); }
.aga-field-hint { font-size: 11px; color: var(--dim, #4a4460); margin-top: 4px; }

.aga-row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.aga-studio-wrap { display: flex; flex-direction: column; gap: 8px; }
.aga-select { background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%237a6fa0' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 12px center; padding-right: 36px; }
.aga-select option { background: #1c1830; }

/* Source buttons */
.aga-source-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px; }
.aga-source-btn {
  display: flex; flex-direction: column; align-items: center; gap: 4px;
  padding: 14px 10px; border-radius: 14px;
  background: var(--surface2, #1c1830); border: 1.5px solid var(--border, #2a2540);
  cursor: pointer; transition: all .15s; color: var(--text, #f0eeff);
}
.aga-source-btn:hover { border-color: rgba(139,92,246,.4); }
.aga-source-btn.active {
  border-color: var(--purple, #8b5cf6);
  background: rgba(139,92,246,.1);
  box-shadow: 0 0 0 3px rgba(139,92,246,.12);
}
.aga-source-icon { font-size: 22px; }
.aga-source-name {
  font-family: 'Syne', sans-serif; font-size: 12px; font-weight: 700;
  color: var(--text, #f0eeff);
}
.aga-source-desc { font-size: 10px; color: var(--muted, #7a6fa0); }

/* Toggle */
.aga-toggle-row {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 14px; background: var(--surface2, #1c1830);
  border: 1px solid var(--border, #2a2540); border-radius: 12px; margin-bottom: 10px;
}
.aga-toggle-label {
  font-family: 'Syne', sans-serif; font-size: 12px; font-weight: 700;
  color: var(--text, #f0eeff);
}
.aga-toggle-hint { font-size: 11px; color: var(--muted, #7a6fa0); margin-top: 2px; }
.aga-toggle {
  width: 44px; height: 26px; border-radius: 13px; border: none;
  background: var(--border, #2a2540); cursor: pointer; position: relative;
  transition: background .2s; flex-shrink: 0; padding: 0;
}
.aga-toggle[data-on="true"] { background: var(--purple, #8b5cf6); }
.aga-toggle-knob {
  position: absolute; top: 3px; left: 3px; width: 20px; height: 20px;
  border-radius: 50%; background: #fff; transition: left .2s;
  pointer-events: none;
}
.aga-toggle[data-on="true"] .aga-toggle-knob { left: 21px; }

/* Quick tags */
.aga-quick-tags {
  display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; margin-top: -2px;
}
.aga-qtag {
  padding: 4px 10px; border-radius: 20px; font-size: 11px; font-family: 'Inter', sans-serif;
  background: var(--surface2, #1c1830); border: 1px solid var(--border, #2a2540);
  color: var(--muted, #7a6fa0); cursor: pointer; transition: all .1s;
  user-select: none;
}
.aga-qtag:hover { border-color: rgba(139,92,246,.4); color: var(--text, #f0eeff); }
.aga-qtag.selected {
  background: rgba(139,92,246,.15); border-color: var(--purple, #8b5cf6);
  color: var(--purple2, #c4b5fd);
}

/* Opts checkboxes */
.aga-opts-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.aga-opt-chip {
  display: flex; align-items: center; gap: 6px; padding: 7px 12px;
  border-radius: 20px; border: 1.5px solid var(--border, #2a2540);
  background: var(--surface2, #1c1830); cursor: pointer; font-size: 12px;
  color: var(--muted, #7a6fa0); transition: all .15s; user-select: none;
}
.aga-opt-chip input { display: none; }
.aga-opt-chip:has(input:checked) {
  border-color: var(--purple, #8b5cf6); background: rgba(139,92,246,.12);
  color: var(--purple2, #c4b5fd);
}

/* Footer */
.aga-footer {
  padding: 12px 16px 16px; border-top: 1px solid var(--border, #2a2540);
  display: flex; align-items: center; gap: 10px; flex-shrink: 0;
}
.aga-status { flex: 1; font-size: 12px; min-height: 18px; }
.aga-status.ok  { color: #34d399; }
.aga-status.err { color: #f87171; }
.aga-footer-btns { display: flex; gap: 8px; }
.aga-btn {
  padding: 10px 18px; border-radius: 12px; font-family: 'Syne', sans-serif;
  font-size: 13px; font-weight: 700; cursor: pointer; border: none;
  display: flex; align-items: center; gap: 6px; transition: all .15s;
}
.aga-btn-cancel {
  background: var(--surface2, #1c1830); border: 1px solid var(--border, #2a2540);
  color: var(--muted, #7a6fa0);
}
.aga-btn-cancel:hover { border-color: rgba(139,92,246,.4); color: var(--text, #f0eeff); }
.aga-btn-submit {
  background: linear-gradient(135deg, #8b5cf6, #7c3aed);
  color: #fff; box-shadow: 0 4px 16px rgba(139,92,246,.35);
}
.aga-btn-submit:hover { transform: translateY(-1px); box-shadow: 0 6px 24px rgba(139,92,246,.45); }
.aga-btn-submit:active { transform: none; }
.aga-btn-submit:disabled { opacity: .5; cursor: default; transform: none; }

/* Spinner */
.aga-spinner {
  width: 14px; height: 14px; border-radius: 50%;
  border: 2px solid rgba(255,255,255,.3); border-top-color: #fff;
  animation: aga-spin .7s linear infinite;
}
@keyframes aga-spin { to { transform: rotate(360deg); } }

/* ── Кнопка в профиле ────────────────────────────────── */
.admin-add-game-btn {
  display: flex; align-items: center; gap: 10px;
  width: 100%; padding: 13px 18px;
  background: linear-gradient(135deg, rgba(139,92,246,.12), rgba(109,40,217,.08));
  border: 1.5px solid rgba(139,92,246,.3); border-radius: 14px;
  color: var(--purple2, #c4b5fd); font-family: 'Syne', sans-serif;
  font-size: 13px; font-weight: 700; cursor: pointer;
  transition: all .15s; margin: 0 0 12px;
}
.admin-add-game-btn:hover {
  border-color: rgba(139,92,246,.6);
  background: linear-gradient(135deg, rgba(139,92,246,.18), rgba(109,40,217,.12));
  transform: translateY(-1px);
}
.admin-add-game-btn .aagb-icon {
  width: 32px; height: 32px; border-radius: 9px;
  background: linear-gradient(135deg, #8b5cf6, #6d28d9);
  display: flex; align-items: center; justify-content: center; font-size: 16px;
  box-shadow: 0 2px 8px rgba(139,92,246,.4);
}

@media (max-width: 480px) {
  .aga-row2 { grid-template-columns: 1fr; }
  .aga-source-grid { grid-template-columns: 1fr 1fr; }
}

/* ── Кнопка ✏️ на странице игры ──────────────────────── */
.admin-edit-game-btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 14px; border-radius: 11px; flex-shrink: 0;
  background: rgba(139,92,246,.1);
  border: 1.5px solid rgba(139,92,246,.35);
  color: var(--purple2, #c4b5fd);
  font-family: 'Syne', sans-serif; font-size: 12px; font-weight: 700;
  cursor: pointer; transition: all .15s;
  white-space: nowrap;
}
.admin-edit-game-btn:hover {
  background: rgba(139,92,246,.2);
  border-color: rgba(139,92,246,.65);
  transform: translateY(-1px);
}
    `;
    document.head.appendChild(style);
  }

  // ── Популярные теги ───────────────────────────────────────────
  const QUICK_TAGS = [
    'Открытый мир','Сюжет','Экшн','RPG','Шутер','Кооп','Хоррор',
    'Выживание','Симулятор','Стратегия','Мультиплеер','Хардкор',
    'Атмосфера','Инди','Файтинг','Платформер','Roguelike','Пиксели',
    'Головоломка','Расслабляющее','Юмор','Стелс','Гонки','Крафт',
  ];

  // ── Инициализация логики ──────────────────────────────────────
  function _initLogic() {
    const $ = id => document.getElementById(id);

    // Studio select logic
    const studioSel    = $('agaStudioSelect');
    const studioCustom = $('agaStudioCustom');
    const studioHint   = $('agaStudioHint');

    studioSel.addEventListener('change', () => {
      if (studioSel.value === '__custom__') {
        studioCustom.style.display = 'block';
        studioCustom.focus();
        studioHint.textContent = 'Если студия неизвестна — оставьте «Инди • Разное»';
      } else {
        studioCustom.style.display = 'none';
        studioHint.textContent = '';
      }
    });

    // Steam ID → preview
    const steamIdInp = $('agaSteamId');
    const previewBox = $('agaPreview');
    const previewImg = $('agaPreviewImg');
    const previewPh  = $('agaPreviewPlaceholder');
    const previewOv  = $('agaPreviewOverlay');
    const previewTit = $('agaPreviewTitle');
    const titleInp   = $('agaTitle');

    let _previewTimer;
    function _updatePreview() {
      const id = steamIdInp.value.trim();
      if (!id || !/^\d+$/.test(id)) {
        previewImg.style.display = 'none';
        previewOv.style.display  = 'none';
        previewPh.style.display  = 'flex';
        previewBox.classList.remove('has-img');
        return;
      }
      const url = `https://cdn.cloudflare.steamstatic.com/steam/apps/${id}/header.jpg`;
      previewImg.src = url;
      previewImg.style.display = 'block';
      previewPh.style.display  = 'none';
      previewBox.classList.add('has-img');
      previewImg.onload = () => {
        previewOv.style.display = 'flex';
        previewTit.textContent  = titleInp.value || '';
      };
      previewImg.onerror = () => {
        previewImg.style.display = 'none';
        previewOv.style.display  = 'none';
        previewPh.style.display  = 'flex';
        previewBox.classList.remove('has-img');
      };
    }
    steamIdInp.addEventListener('input', () => {
      clearTimeout(_previewTimer);
      _previewTimer = setTimeout(_updatePreview, 500);
    });
    titleInp.addEventListener('input', () => {
      previewTit.textContent = titleInp.value || '';
    });

    // Source toggle
    let currentSource = 'local';
    const srcBtns = document.querySelectorAll('.aga-source-btn');
    const steampassRow = $('agaSteampassRow');

    function _setSource(s) {
      currentSource = s;
      srcBtns.forEach(b => b.classList.toggle('active', b.dataset.source === s));
      steampassRow.style.display = (s === 'steam') ? 'block' : 'none';
    }
    _setSource('local');
    srcBtns.forEach(b => b.addEventListener('click', () => _setSource(b.dataset.source)));

    // DLC toggle
    const dlcToggle = $('agaDlcToggle');
    dlcToggle.addEventListener('click', () => {
      const on = dlcToggle.dataset.on === 'true';
      dlcToggle.dataset.on = String(!on);
    });

    // Marme toggle
    const marmeToggle = $('agaMarmeToggle');
    marmeToggle.addEventListener('click', () => {
      const on = marmeToggle.dataset.on === 'true';
      marmeToggle.dataset.on = String(!on);
    });

    // Quick tags
    const quickTagsEl = $('agaQuickTags');
    const tagsInput   = $('agaTags');
    let selectedQuickTags = new Set();

    QUICK_TAGS.forEach(tag => {
      const btn = document.createElement('button');
      btn.className = 'aga-qtag';
      btn.type = 'button';
      btn.textContent = tag;
      btn.addEventListener('click', () => {
        if (selectedQuickTags.has(tag)) {
          selectedQuickTags.delete(tag);
          btn.classList.remove('selected');
        } else {
          selectedQuickTags.add(tag);
          btn.classList.add('selected');
        }
        _syncTagsInput();
      });
      quickTagsEl.appendChild(btn);
    });

    function _syncTagsInput() {
      const manual = tagsInput.value.split(',').map(s => s.trim()).filter(s => s && !selectedQuickTags.has(s));
      const all    = [...selectedQuickTags, ...manual];
      tagsInput.value = all.join(', ');
    }

    // Close
    const overlay = $('agaOverlay');
    $('agaClose').addEventListener('click', close);
    $('agaCancel').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });

    // Submit
    $('agaSubmit').addEventListener('click', async () => {
      await _submit({ currentSource, selectedQuickTags });
    });

    // ── Prefill при редактировании ──────────────────────────
    if (_editGame) {
      const g = _editGame;
      $('agaTitle').value   = g.title  || '';
      $('agaShort').value   = g.short  || '';
      $('agaSteamId').value = String(g.steamId || g.steam_id || '');
      if ($('agaSteampassUrl')) $('agaSteampassUrl').value = g.steampassUrl || '';

      // Студия
      const knownOpt = [...studioSel.options].find(o => o.value === g.group);
      if (knownOpt) { studioSel.value = g.group; }
      else if (g.group) {
        studioSel.value = '__custom__';
        studioCustom.style.display = 'block';
        studioCustom.value = g.group;
      }

      // Источник
      _setSource(g.source || 'local');

      // Toggles
      dlcToggle.dataset.on   = String(!!g.hasDlc);
      marmeToggle.dataset.on = String(!!g.marme1adker);

      // Теги
      const gameTags = g.tags || [];
      quickTagsEl.querySelectorAll('.aga-qtag').forEach(btn => {
        if (gameTags.includes(btn.textContent)) {
          btn.classList.add('selected');
          selectedQuickTags.add(btn.textContent);
        }
      });
      tagsInput.value = gameTags.join(', ');

      // Opts
      const opts = g.opts || [];
      $('agaChkDlc').checked    = opts.includes('dlc');
      $('agaChkRu').checked     = opts.includes('ru');
      $('agaChkOnline').checked = opts.includes('online');

      // Превью
      _updatePreview();
    }

    return { currentSource: () => currentSource, getMarme: () => marmeToggle.dataset.on === 'true', getDlc: () => dlcToggle.dataset.on === 'true' };
  }

  // ── Убедиться что игра есть в БД (для локальных игр из data.js) ──
  // Если игра найдена в БД — возвращает её id.
  // Если НЕ найдена — добавляет через /api/admin/games/add и возвращает id.
  // Если игра уже есть (409) — это нормально, продолжаем по title.
  async function _ensureInDb(game) {
    const base  = _getApiBase();
    const token = _getToken();

    // Пробуем добавить игру в БД
    const steamId = game.steamId || game.steam_id || 0;
    const payload = {
      title:        game.title,
      short:        game.short        || '',
      group:        game.group        || 'Инди • Разное',
      hasDlc:       !!game.hasDlc,
      source:       game.source       || 'local',
      marme1adker:  !!game.marme1adker,
      steamId:      typeof steamId === 'string' ? parseInt(steamId, 10) : (steamId || 0),
      steampassUrl: game.steampassUrl || null,
      tags:         game.tags         || [],
      opts:         game.opts         || [],
    };

    const addRes = await fetch(`${base}/api/admin/games/add`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(payload),
    });

    if (addRes.status === 409) {
      // Уже существует — ищем по title при PATCH (вернём null, title сработает)
      return null;
    }

    if (!addRes.ok) {
      const err = await addRes.json().catch(() => ({}));
      throw new Error(err.detail || `Не удалось синхронизировать игру с БД: ${addRes.status}`);
    }

    // Успешно добавлена — возвращаем id из ответа если есть
    const addData = await addRes.json().catch(() => ({}));
    return addData.id || null;
  }

  // ── Submit ────────────────────────────────────────────────────
  async function _submit() {
    const $ = id => document.getElementById(id);

    const title       = $('agaTitle').value.trim();
    const short       = $('agaShort').value.trim();
    const steamId     = $('agaSteamId').value.trim();
    const tagsRaw     = $('agaTags').value;
    const steampassUrl = $('agaSteampassUrl').value.trim();
    const hasDlc      = $('agaDlcToggle').dataset.on === 'true';
    const marme1adker = $('agaMarmeToggle').dataset.on === 'true';
    const source      = document.querySelector('.aga-source-btn.active')?.dataset.source || 'local';

    // Studio
    const studioSel  = $('agaStudioSelect');
    let   group      = studioSel.value === '__custom__' || studioSel.value === ''
      ? ($('agaStudioCustom').value.trim() || 'Инди • Разное')
      : studioSel.value;
    if (!group) group = 'Инди • Разное';

    // Opts
    const opts = [];
    if ($('agaChkDlc').checked)    opts.push('dlc');
    if ($('agaChkRu').checked)     opts.push('ru');
    if ($('agaChkOnline').checked) opts.push('online');
    if (hasDlc && !opts.includes('dlc')) opts.push('dlc');

    // Tags
    const tags = tagsRaw.split(',').map(s => s.trim()).filter(Boolean);

    // Validate
    const statusEl  = $('agaStatus');
    const submitBtn = $('agaSubmit');
    const submitTxt = $('agaSubmitText');
    const spinner   = $('agaSpinner');

    $('agaTitle').classList.remove('error');
    $('agaSteamId').classList.remove('error');
    statusEl.textContent = '';
    statusEl.className   = 'aga-status';

    if (!title) {
      $('agaTitle').classList.add('error');
      statusEl.textContent = '⚠️ Введите название игры';
      statusEl.className   = 'aga-status err';
      $('agaTitle').focus();
      return;
    }
    if (!steamId || !/^\d+$/.test(steamId)) {
      $('agaSteamId').classList.add('error');
      statusEl.textContent = '⚠️ Введите корректный Steam AppID';
      statusEl.className   = 'aga-status err';
      $('agaSteamId').focus();
      return;
    }

    // Loading state
    submitBtn.disabled  = true;
    submitTxt.style.display = 'none';
    spinner.style.display   = 'inline-block';
    statusEl.textContent = 'Отправляю...';

    const payload = {
      title, short, group, hasDlc, source, marme1adker,
      steamId: parseInt(steamId, 10),
      steampassUrl: steampassUrl || null,
      tags, opts,
    };

    try {
      const base   = _getApiBase();
      const token  = _getToken();
      const isEdit  = !!_editGame;

      // Если редактируем — убеждаемся что игра есть в БД
      // (локальные игры из data.js могут не быть в SQLite)
      let resolvedId = _editGame?.id || null;
      if (isEdit && !resolvedId) {
        statusEl.textContent = '🔍 Синхронизация с базой данных...';
        try {
          resolvedId = await _ensureInDb(_editGame);
        } catch (syncErr) {
          statusEl.textContent = `❌ ${syncErr.message}`;
          statusEl.className   = 'aga-status err';
          submitBtn.disabled  = false;
          submitTxt.style.display = '';
          spinner.style.display   = 'none';
          return;
        }
        statusEl.textContent = 'Отправляю...';
      }

      // id надёжнее title — используем его если есть
      const gameRef = isEdit
        ? (resolvedId ? String(resolvedId) : encodeURIComponent(_editGame.title))
        : null;
      const url     = isEdit
        ? `${base}/api/admin/games/${gameRef}`
        : `${base}/api/admin/games/add`;

      const res = await fetch(url, {
        method: isEdit ? 'PATCH' : 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(payload),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.detail || `Ошибка ${res.status}`);
      }

      statusEl.textContent = isEdit ? `✅ ${title} обновлена!` : `✅ ${title} добавлена в каталог!`;
      statusEl.className   = 'aga-status ok';

      // Перезагрузить каталог без reload страницы
      if (typeof fetchGames === 'function' && typeof ALL !== 'undefined') {
        try {
          const games = await fetchGames();
          ALL.length  = 0;
          games.forEach(g => ALL.push(g));
          if (typeof render === 'function') render();
          if (typeof showToast === 'function') showToast(`🎮 ${title} добавлена в каталог!`);
        } catch(e) {
          console.warn('[AdminAddGame] reload failed:', e);
        }
      }

      setTimeout(() => close(), 1800);

    } catch (err) {
      statusEl.textContent = `❌ ${err.message}`;
      statusEl.className   = 'aga-status err';
    } finally {
      submitBtn.disabled  = false;
      submitTxt.style.display = '';
      spinner.style.display   = 'none';
    }
  }

  // ── Open / Close ──────────────────────────────────────────────
  function open(gameToEdit = null) {
    if (!Auth || !Auth.isAdmin()) {
      console.warn('[AdminAddGame] Not admin');
      return;
    }

    _editGame = gameToEdit || null;
    const editMode = !!_editGame;

    _injectStyles();

    // Remove previous if exists
    document.getElementById('agaOverlay')?.remove();

    // Inject HTML
    const tmp = document.createElement('div');
    tmp.innerHTML = _buildHTML(editMode);
    document.body.appendChild(tmp.firstElementChild);

    _initLogic();

    // Animate in
    requestAnimationFrame(() => {
      document.getElementById('agaOverlay')?.classList.add('open');
    });

    document.body.style.overflow = 'hidden';
  }

  function close() {
    const overlay = document.getElementById('agaOverlay');
    if (!overlay) return;
    overlay.classList.remove('open');
    setTimeout(() => {
      overlay.remove();
      document.body.style.overflow = '';
    }, 300);
  }

  // ── Создать кнопку для профиля ────────────────────────────────
  function createProfileButton() {
    const btn = document.createElement('button');
    btn.className = 'admin-add-game-btn';
    btn.id = 'adminAddGameBtn';
    btn.innerHTML = `
      <div class="aagb-icon">➕</div>
      <span>Добавить игру в каталог</span>
    `;
    btn.addEventListener('click', open);
    return btn;
  }

  /**
   * Вставить кнопку в профиль (вызывается из loadProfile после рендера).
   * Ищет зону с "Последние игры" и вставляет кнопку перед ней.
   */
  function injectIntoProfile() {
    if (!Auth || !Auth.isAdmin()) return;
    if (document.getElementById('adminAddGameBtn')) return;

    _injectStyles();

    // Ищем блок «Последние игры» по внутреннему тексту
    let insertPoint = null;
    document.querySelectorAll('h3').forEach(h => {
      if (h.textContent.includes('Последние игры')) {
        insertPoint = h.closest('[style]') || h.parentElement?.parentElement;
      }
    });

    // Fallback — ищем profLastGames
    if (!insertPoint) {
      const pg = document.getElementById('profLastGames');
      insertPoint = pg?.closest('[style]') || pg?.parentElement?.parentElement;
    }

    const btn = createProfileButton();

    // Кнопка «Импорт локальных игр в БД»
    const seedBtn = document.createElement('button');
    seedBtn.className = 'admin-add-game-btn';
    seedBtn.id = 'adminSeedBtn';
    seedBtn.innerHTML = `
      <div class="aagb-icon">⬆️</div>
      <span>Импортировать каталог в БД</span>
    `;
    seedBtn.addEventListener('click', async () => {
      seedBtn.disabled = true;
      seedBtn.querySelector('span').textContent = 'Импортирую...';
      await AdminSeed.run();
      seedBtn.querySelector('span').textContent = '✅ Готово!';
      setTimeout(() => {
        seedBtn.querySelector('span').textContent = 'Импортировать каталог в БД';
        seedBtn.disabled = false;
      }, 3000);
    });

    if (insertPoint && insertPoint.parentNode) {
      insertPoint.parentNode.insertBefore(btn, insertPoint);
      insertPoint.parentNode.insertBefore(seedBtn, insertPoint);
    } else {
      const sec = document.getElementById('section-profile');
      const zone = sec?.querySelector('[style*="padding-bottom"]');
      if (zone) { zone.appendChild(btn); zone.appendChild(seedBtn); }
    }
  }

  // ── openEdit — открыть в режиме редактирования ─────────────
  function openEdit(game) { open(game); }

  return { open, openEdit, close, injectIntoProfile, createProfileButton };

})();