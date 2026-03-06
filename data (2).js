/**
 * data.js — источник данных каталога
 *
 * Локальный массив — всегда загружается мгновенно.
 * При старте делает запрос к API и добавляет новые игры (добавленные через админку).
 *
 * source: 'local' | 'steam'
 *   local = мгновенно из локальной базы (⚡)
 *   steam = через Steampass — База данных (🔵)
 */

const steamImg = id =>
  `https://cdn.cloudflare.steamstatic.com/steam/apps/${id}/header.jpg`;

// ── Локальный каталог (всегда доступен) ─────────────────────────
const _localGames = [

    // ── Rockstar ─────────────────────────────────────────────────
    { title: 'Grand Theft Auto V',                    short: 'GTA V',              group: 'Rockstar',            img: steamImg(271590),   hasDlc: true,  tags: ['Открытый мир', 'Шутер', 'Экшн', 'Кооп'],          opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Red Dead Redemption 2',                 short: 'RDR2',               group: 'Rockstar',            img: steamImg(1174180),  hasDlc: true,  tags: ['Открытый мир', 'Сюжет', 'Вестерн'],               opts: ['dlc'],            source: 'steam' ,  marme1adker: true },
    { title: 'Red Dead Redemption',                   short: 'RDR1',               group: 'Rockstar',            img: steamImg(2668510),                tags: ['Открытый мир', 'Вестерн', 'Сюжет'],               opts: [],                 source: 'steam' },
    { title: 'Grand Theft Auto: San Andreas',         short: 'GTA SA',             group: 'Rockstar',            img: steamImg(12120),                  tags: ['Открытый мир', 'Экшн'],                           opts: [],                 source: 'steam' },
    { title: 'Grand Theft Auto: Vice City',           short: 'GTA Vice City',      group: 'Rockstar',            img: steamImg(12110),                  tags: ['Открытый мир', 'Экшн'],                           opts: [],                 source: 'steam' },
    { title: 'Grand Theft Auto III',                  short: 'GTA III',            group: 'Rockstar',            img: steamImg(12100),                  tags: ['Открытый мир', 'Экшн'],                           opts: [],                 source: 'steam' },

    // ── CD Projekt Red ───────────────────────────────────────────
    { title: 'Cyberpunk 2077',                        short: 'Cyberpunk',          group: 'CD Projekt Red',      img: steamImg(1091500),  hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Сюжет', 'Экшн'],           opts: ['dlc', 'ru'],      source: 'local' ,  marme1adker: true },

    // ── Ubisoft ──────────────────────────────────────────────────
    { title: "Assassin's Creed Shadows",              short: 'AC Shadows',         group: 'Ubisoft',             img: steamImg(3159330),  hasDlc: true,  tags: ['Открытый мир', 'Стелс', 'Экшн', 'Самурай'],       opts: ['dlc'],            source: 'steam' },
    { title: "Assassin's Creed Mirage",               short: 'AC Mirage',          group: 'Ubisoft',             img: steamImg(3035570),  hasDlc: true,  tags: ['Открытый мир', 'Стелс', 'Экшн'],                  opts: ['dlc'],            source: 'steam' },
    { title: "Assassin's Creed Valhalla",             short: 'AC Valhalla',        group: 'Ubisoft',             img: steamImg(2208920),  hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Экшн', 'Викинги'],         opts: ['dlc'],            source: 'steam' },
    { title: "Assassin's Creed Odyssey",              short: 'AC Odyssey',         group: 'Ubisoft',             img: steamImg(812140),   hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Экшн'],                    opts: ['dlc'],            source: 'steam' },
    { title: "Assassin's Creed II",                   short: 'AC II',              group: 'Ubisoft',             img: steamImg(33230),                  tags: ['Открытый мир', 'Стелс', 'Экшн'],                  opts: [],                 source: 'local' },
    { title: 'Far Cry 6',                             short: 'Far Cry 6',          group: 'Ubisoft',             img: steamImg(2369390),  hasDlc: true,  tags: ['Открытый мир', 'Шутер', 'Экшн'],                  opts: ['dlc'],            source: 'steam' },
    { title: 'Far Cry 5',                             short: 'Far Cry 5',          group: 'Ubisoft',             img: steamImg(552520),   hasDlc: true,  tags: ['Открытый мир', 'Шутер', 'Кооп'],                  opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Watch Dogs',                            short: 'Watch Dogs 1',       group: 'Ubisoft',             img: steamImg(243470),                 tags: ['Открытый мир', 'Хакинг', 'Экшн'],                 opts: [],                 source: 'local' },
    { title: 'Watch Dogs 2',                          short: 'Watch Dogs 2',       group: 'Ubisoft',             img: steamImg(447040),   hasDlc: true,  tags: ['Открытый мир', 'Хакинг', 'Экшн'],                 opts: ['dlc'],            source: 'steam' },
    { title: 'Watch Dogs: Legion',                    short: 'Watch Dogs Legion',  group: 'Ubisoft',             img: steamImg(2239550),  hasDlc: true,  tags: ['Открытый мир', 'Хакинг', 'Кооп'],                 opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'For Honor',                             short: 'For Honor',          group: 'Ubisoft',             img: steamImg(304390),   hasDlc: true,  tags: ['Файтинг', 'Кооп', 'Мультиплеер'],                 opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Just Cause 4',                          short: 'Just Cause 4',       group: 'Ubisoft',             img: steamImg(517630),   hasDlc: true,  tags: ['Открытый мир', 'Экшн', 'Взрывы'],                 opts: ['dlc'],            source: 'local' },

    // ── Valve ────────────────────────────────────────────────────
    { title: 'Half-Life',                             short: 'Half-Life 1',        group: 'Valve',               img: steamImg(70),                     tags: ['Шутер', 'Классика', 'Сюжет'],                     opts: [],                 source: 'local' },
    { title: 'Half-Life 2',                           short: 'Half-Life 2',        group: 'Valve',               img: steamImg(220),                    tags: ['Шутер', 'Классика', 'Сюжет'],                     opts: [],                 source: 'local' },
    { title: 'Portal',                                short: 'Portal 1',           group: 'Valve',               img: steamImg(400),                    tags: ['Головоломка', 'Классика', 'Сюжет'],               opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Portal 2',                              short: 'Portal 2',           group: 'Valve',               img: steamImg(620),                    tags: ['Головоломка', 'Кооп', 'Сюжет'],                   opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'Left 4 Dead',                           short: 'L4D',                group: 'Valve',               img: steamImg(500),                    tags: ['Зомби', 'Кооп', 'Хоррор', 'Шутер'],              opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'Left 4 Dead 2',                         short: 'L4D2',               group: 'Valve',               img: steamImg(550),                    tags: ['Зомби', 'Кооп', 'Хоррор', 'Шутер'],              opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: "Garry's Mod",                           short: 'GMod',               group: 'Valve',               img: steamImg(4000),                   tags: ['Песочница', 'Кооп', 'Для всех'],                  opts: ['online'],         source: 'local' },

    // ── FromSoftware ─────────────────────────────────────────────
    { title: 'ELDEN RING',                            short: 'Elden Ring',         group: 'FromSoftware',        img: steamImg(1245620),  hasDlc: true,  tags: ['Souls-like', 'Открытый мир', 'Хардкор'],           opts: ['dlc'],            source: 'local' ,  marme1adker: true },
    { title: 'Dark Souls III',                        short: 'DS3',                group: 'FromSoftware',        img: steamImg(374320),   hasDlc: true,  tags: ['Souls-like', 'Хардкор', 'Экшн'],                  opts: ['dlc'],            source: 'local' },
    { title: 'Sekiro: Shadows Die Twice',             short: 'Sekiro',             group: 'FromSoftware',        img: steamImg(814380),                 tags: ['Souls-like', 'Хардкор', 'Стелс'],                 opts: [],                 source: 'local' },
    { title: 'Armored Core VI: Fires of Rubicon',    short: 'AC6',                group: 'FromSoftware',        img: steamImg(1888160),  hasDlc: true,  tags: ['Роботы', 'Хардкор', 'Экшн'],                      opts: ['dlc'],            source: 'steam' },

    // ── PlayStation Studios ───────────────────────────────────────
    { title: "Marvel's Spider-Man 2",                 short: 'Spider-Man 2',       group: 'PlayStation',         img: steamImg(2651280),  hasDlc: true,  tags: ['Открытый мир', 'Экшн', 'Супергерой'],             opts: ['dlc'],            source: 'steam' },
    { title: 'God of War Ragnarök',                   short: 'GoW Ragnarök',       group: 'PlayStation',         img: steamImg(2322010),  hasDlc: true,  tags: ['Экшн', 'Сюжет', 'Мифология'],                     opts: ['dlc'],            source: 'local' },
    { title: "Ghost of Tsushima DIRECTOR'S CUT",      short: 'Ghost of Tsushima',  group: 'PlayStation',         img: steamImg(2215430),  hasDlc: true,  tags: ['Открытый мир', 'Самурай', 'Стелс'],               opts: ['dlc'],            source: 'local' },
    { title: 'The Last of Us Part I',                 short: 'TLOU 1',             group: 'PlayStation',         img: steamImg(1888930),                tags: ['Хоррор', 'Сюжет', 'Выживание'],                   opts: [],                 source: 'local' },
    { title: 'The Last of Us Part II Remastered',     short: 'TLOU 2',             group: 'PlayStation',         img: steamImg(2531310),  hasDlc: true,  tags: ['Хоррор', 'Сюжет', 'Выживание'],                   opts: ['dlc'],            source: 'steam' },
    { title: 'Helldivers 2',                          short: 'Helldivers 2',       group: 'PlayStation',         img: steamImg(553850),   hasDlc: true,  tags: ['Кооп', 'Шутер', 'Мультиплеер'],                   opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Detroit: Become Human',                 short: 'Detroit',            group: 'PlayStation',         img: steamImg(1222140),                tags: ['Сюжет', 'Интерактивное кино', 'Фантастика'],       opts: [],                 source: 'local' ,  marme1adker: true },
    { title: "Death Stranding Director's Cut",        short: 'Death Stranding',    group: 'PlayStation',         img: steamImg(1850570),  hasDlc: true,  tags: ['Открытый мир', 'Сюжет', 'Необычное'],             opts: ['dlc'],            source: 'steam' },
    { title: 'God of War',                            short: 'God of War 2018',    group: 'PlayStation',         img: steamImg(1593500),                tags: ['Экшн', 'Сюжет', 'Мифология'],                     opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Days Gone',                             short: 'Days Gone',          group: 'PlayStation',         img: steamImg(1259420),                tags: ['Открытый мир', 'Зомби', 'Выживание'],             opts: [],                 source: 'steam' },
    { title: 'Beyond: Two Souls',                     short: 'Beyond',             group: 'PlayStation',         img: steamImg(1372890),                tags: ['Сюжет', 'Интерактивное кино', 'Фантастика'],       opts: [],                 source: 'local' },
    { title: 'Heavy Rain',                            short: 'Heavy Rain',         group: 'PlayStation',         img: steamImg(960090),                 tags: ['Сюжет', 'Интерактивное кино', 'Детектив'],         opts: [],                 source: 'local' },
    { title: 'Dying Light',                           short: 'Dying Light 1',      group: 'PlayStation',         img: steamImg(239140),   hasDlc: true,  tags: ['Открытый мир', 'Зомби', 'Паркур', 'Кооп'],        opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Dying Light 2',                         short: 'DL2',                group: 'PlayStation',         img: steamImg(534380),   hasDlc: true,  tags: ['Открытый мир', 'Зомби', 'Паркур', 'Кооп'],        opts: ['dlc', 'online'],  source: 'local' },

    // ── Gearbox ──────────────────────────────────────────────────
    { title: 'Borderlands 3',                         short: 'BL3',                group: 'Gearbox',             img: steamImg(397540),   hasDlc: true,  tags: ['Шутер', 'RPG', 'Кооп', 'Юмор'],                   opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Borderlands 2',                         short: 'BL2',                group: 'Gearbox',             img: steamImg(49520),    hasDlc: true,  tags: ['Шутер', 'RPG', 'Кооп', 'Юмор'],                   opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },

    // ── Bethesda ─────────────────────────────────────────────────
    { title: 'Fallout 4',                             short: 'FO4',                group: 'Bethesda',            img: steamImg(377160),   hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Постапокалипсис'],          opts: ['dlc', 'ru'],      source: 'local' },
    { title: 'Fallout: New Vegas',                    short: 'FNV',                group: 'Bethesda',            img: steamImg(22380),    hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Постапокалипсис'],          opts: ['dlc'],            source: 'local' },
    { title: 'Fallout 3',                             short: 'FO3',                group: 'Bethesda',            img: steamImg(22300),    hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Постапокалипсис'],          opts: ['dlc'],            source: 'steam' },
    { title: 'Fallout 76',                            short: 'FO76',               group: 'Bethesda',            img: steamImg(1151340),  hasDlc: true,  tags: ['Открытый мир', 'Мультиплеер', 'Постапокалипсис'], opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'The Elder Scrolls V: Skyrim Special Edition', short: 'Skyrim',       group: 'Bethesda',            img: steamImg(489830),   hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Фэнтези'],                 opts: ['dlc', 'ru'],      source: 'local' ,  marme1adker: true },
    { title: 'Starfield',                             short: 'Starfield',          group: 'Bethesda',            img: steamImg(1716740),  hasDlc: true,  tags: ['Открытый мир', 'RPG', 'Фантастика'],               opts: ['dlc', 'ru'],      source: 'steam' },

    // ── 2K / Firaxis ─────────────────────────────────────────────
    { title: 'Civilization V',                        short: 'Civ 5',              group: '2K',                  img: steamImg(8930),     hasDlc: true,  tags: ['Стратегия', 'Пошаговая', 'История'],              opts: ['dlc'],            source: 'local' },
    { title: 'Civilization VI',                       short: 'Civ 6',              group: '2K',                  img: steamImg(289070),   hasDlc: true,  tags: ['Стратегия', 'Пошаговая', 'История'],              opts: ['dlc'],            source: 'local' },
    { title: 'Mafia',                                 short: 'Mafia 1',            group: '2K',                  img: steamImg(40990),                  tags: ['Экшн', 'Сюжет', 'Криминал', 'Классика'],          opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Mortal Kombat 11',                      short: 'MK11',               group: '2K',                  img: steamImg(976310),   hasDlc: true,  tags: ['Файтинг', 'Мультиплеер'],                         opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Mortal Kombat X',                       short: 'MKX',                group: '2K',                  img: steamImg(307780),   hasDlc: true,  tags: ['Файтинг', 'Мультиплеер'],                         opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Bioshock Infinite',                     short: 'Bioshock Inf.',      group: '2K',                  img: steamImg(8870),     hasDlc: true,  tags: ['Шутер', 'Сюжет', 'Фантастика'],                   opts: ['dlc'],            source: 'steam' },
    { title: 'Mafia: Definitive Edition',             short: 'Mafia DE',           group: '2K',                  img: steamImg(1030840),                tags: ['Экшн', 'Сюжет', 'Криминал'],                     opts: ['ru'],             source: 'local' },
    { title: 'Mafia II: Definitive Edition',          short: 'Mafia II DE',        group: '2K',                  img: steamImg(1030830),                tags: ['Экшн', 'Сюжет', 'Криминал', 'Открытый мир'],     opts: ['ru'],             source: 'local' },

    // ── Paradox ──────────────────────────────────────────────────
    { title: 'Hearts of Iron IV',                     short: 'HOI4',               group: 'Paradox',             img: steamImg(394360),   hasDlc: true,  tags: ['Стратегия', 'ВМВ', 'Глобальная', 'История'],      opts: ['dlc'],            source: 'local' ,  marme1adker: true },

    // ── EA ───────────────────────────────────────────────────────
    { title: 'Battlefield V',                         short: 'BFV',                group: 'EA',                  img: steamImg(877480),   hasDlc: true,  tags: ['Шутер', 'Мультиплеер', 'ВМВ'],                    opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Battlefield 1',                         short: 'BF1',                group: 'EA',                  img: steamImg(1238820),  hasDlc: true,  tags: ['Шутер', 'Мультиплеер', 'ВМВ'],                    opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Battlefield 4',                         short: 'BF4',                group: 'EA',                  img: steamImg(1238820),  hasDlc: true,  tags: ['Шутер', 'Мультиплеер'],                           opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'Need for Speed: Most Wanted',           short: 'NFS MW',             group: 'EA',                  img: steamImg(1222700),                tags: ['Гонки', 'Аркада', 'Открытый мир'],                opts: [],                 source: 'local' },
    { title: 'A Way Out',                             short: 'A Way Out',          group: 'EA',                  img: steamImg(1222730),                tags: ['Кооп', 'Сюжет', 'Приключение'],                   opts: ['online'],         source: 'steam' },

    // ── Activision ───────────────────────────────────────────────
    { title: 'Call of Duty: Modern Warfare 2',        short: 'MW2',                group: 'Activision',          img: steamImg(10180),                  tags: ['Шутер', 'Классика', 'Мультиплеер'],               opts: ['online'],         source: 'local' },

    // ── Microsoft / Racing ───────────────────────────────────────
    { title: 'Forza Horizon 4',                       short: 'FH4',                group: 'Microsoft',           img: steamImg(1293830),  hasDlc: true,  tags: ['Гонки', 'Открытый мир'],                          opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Forza Horizon 5',                       short: 'FH5',                group: 'Microsoft',           img: steamImg(1551360),  hasDlc: true,  tags: ['Гонки', 'Открытый мир'],                          opts: ['dlc', 'online'],  source: 'local' },
    { title: 'BeamNG.drive',                          short: 'BeamNG',             group: 'Microsoft',           img: steamImg(284160),                 tags: ['Гонки', 'Симулятор', 'Физика'],                   opts: [],                 source: 'local' },
    { title: 'Halo Infinite',                         short: 'Halo Infinite',      group: 'Microsoft',           img: steamImg(1240440),                tags: ['Шутер', 'Мультиплеер', 'Фантастика'],             opts: ['online'],         source: 'local', marme1adker: true },
    { title: 'Sea of Thieves',                        short: 'Sea of Thieves',     group: 'Microsoft',           img: steamImg(1172620),                tags: ['Приключение', 'Кооп', 'Открытый мир'],            opts: ['dlc', 'online'],  source: 'local', marme1adker: true },

    // ── Racing studios ───────────────────────────────────────────
    { title: 'Assetto Corsa',                         short: 'Assetto Corsa',      group: 'Kunos',               img: steamImg(244210),   hasDlc: true,  tags: ['Гонки', 'Симулятор'],                             opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'Euro Truck Simulator 2',                short: 'ETS2',               group: 'SCS Software',        img: steamImg(227300),   hasDlc: true,  tags: ['Симулятор', 'Расслабляющее', 'Кооп'],             opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'American Truck Simulator',              short: 'ATS',                group: 'SCS Software',        img: steamImg(270880),   hasDlc: true,  tags: ['Симулятор', 'Расслабляющее'],                     opts: ['dlc', 'online'],  source: 'local' },
    { title: 'DiRT Rally',                            short: 'DiRT Rally',         group: 'Codemasters',         img: steamImg(310560),   hasDlc: true,  tags: ['Гонки', 'Симулятор', 'Хардкор'],                  opts: ['dlc'],            source: 'local' ,  marme1adker: true },
    { title: 'FlatOut 2',                             short: 'FlatOut 2',          group: 'Codemasters',         img: steamImg(2990),                   tags: ['Гонки', 'Аркада', 'Классика'],                    opts: [],                 source: 'local' },
    { title: 'GRID 2',                                short: 'GRID 2',             group: 'Codemasters',         img: steamImg(44350),    hasDlc: true,  tags: ['Гонки', 'Мультиплеер'],                           opts: ['dlc', 'online'],  source: 'local' },
    { title: 'MudRunner',                             short: 'MudRunner',          group: 'Focus',               img: steamImg(675010),   hasDlc: true,  tags: ['Симулятор', 'Бездорожье', 'Кооп'],                opts: ['dlc', 'online'],  source: 'local' },

    // ── Survival / Crafting ───────────────────────────────────────
    { title: 'Terraria',                              short: 'Terraria',           group: 'Инди • Выживание',    img: steamImg(105600),                 tags: ['Выживание', 'Крафт', 'Кооп', 'Песочница'],        opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'Subnautica',                            short: 'Subnautica',         group: 'Инди • Выживание',    img: steamImg(264710),                 tags: ['Выживание', 'Исследование', 'Хоррор'],            opts: [],                 source: 'steam' },
    { title: 'Valheim',                               short: 'Valheim',            group: 'Инди • Выживание',    img: steamImg(892970),   hasDlc: true,  tags: ['Выживание', 'Крафт', 'Кооп', 'Викинги'],          opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'Satisfactory',                          short: 'Satisfactory',       group: 'Инди • Выживание',    img: steamImg(526870),   hasDlc: true,  tags: ['Крафт', 'Строительство', 'Кооп'],                 opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'Project Zomboid',                       short: 'PZ',                 group: 'Инди • Выживание',    img: steamImg(108600),                 tags: ['Выживание', 'Зомби', 'Открытый мир', 'Кооп'],     opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: '7 Days To Die',                         short: '7DTD',               group: 'Инди • Выживание',    img: steamImg(251570),   hasDlc: true,  tags: ['Выживание', 'Зомби', 'Кооп', 'Крафт'],            opts: ['dlc', 'online'],  source: 'local' },
    { title: 'ARK: Survival Evolved',                 short: 'ARK',                group: 'Инди • Выживание',    img: steamImg(346110),   hasDlc: true,  tags: ['Выживание', 'Динозавры', 'Кооп'],                 opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'Sons of the Forest',                    short: 'SOTF',               group: 'Инди • Выживание',    img: steamImg(1326470),                tags: ['Выживание', 'Хоррор', 'Кооп'],                    opts: ['online'],         source: 'local' },
    { title: 'The Forest',                            short: 'The Forest',         group: 'Инди • Выживание',    img: steamImg(242760),                 tags: ['Выживание', 'Хоррор', 'Кооп'],                    opts: ['online'],         source: 'local' },
    { title: 'The Long Dark',                         short: 'TLD',                group: 'Инди • Выживание',    img: steamImg(305620),                 tags: ['Выживание', 'Атмосфера', 'Симулятор'],            opts: [],                 source: 'local' },
    { title: 'Surviving Mars',                        short: 'Surviving Mars',     group: 'Инди • Выживание',    img: steamImg(464920),   hasDlc: true,  tags: ['Стратегия', 'Строительство', 'Фантастика'],        opts: ['dlc'],            source: 'local' },
    { title: 'Raft',                                  short: 'Raft',               group: 'Инди • Выживание',    img: steamImg(648800),                 tags: ['Выживание', 'Крафт', 'Кооп'],                    opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'SnowRunner',                            short: 'SnowRunner',         group: 'Инди • Выживание',    img: steamImg(1465360),  hasDlc: true,  tags: ['Симулятор', 'Бездорожье', 'Кооп'],               opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Manor Lords',                           short: 'Manor Lords',        group: 'Инди • Выживание',    img: steamImg(1363080),                tags: ['Стратегия', 'Строительство', 'Средневековье'],   opts: [],                 source: 'local' },

    // ── Horror ───────────────────────────────────────────────────
    { title: 'Phasmophobia',                          short: 'Phasmo',             group: 'Инди • Хоррор',       img: steamImg(739630),                 tags: ['Хоррор', 'Кооп', 'Атмосфера'],                    opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'Little Nightmares',                     short: 'LN1',                group: 'Инди • Хоррор',       img: steamImg(424840),                 tags: ['Хоррор', 'Платформер', 'Атмосфера'],              opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Tiny Bunny',                            short: 'Tiny Bunny',         group: 'Инди • Хоррор',       img: steamImg(1271690),                tags: ['Хоррор', 'Сюжет', 'Визуальная новелла'],          opts: [],                 source: 'local' },
    { title: 'Amnesia: Rebirth',                      short: 'Amnesia Rebirth',    group: 'Инди • Хоррор',       img: steamImg(999220),                 tags: ['Хоррор', 'Атмосфера', 'Сюжет'],                   opts: [],                 source: 'local' },
    { title: 'Quarantine Zone: The Last Check',       short: 'Quarantine Zone',    group: 'Инди • Хоррор',       img: steamImg(2100250),                tags: ['Хоррор', 'Выживание'],                            opts: [],                 source: 'local' },
    { title: 'Outlast 2',                             short: 'Outlast 2',          group: 'Инди • Хоррор',       img: steamImg(414700),                 tags: ['Хоррор', 'Атмосфера', 'Сюжет'],                   opts: [],                 source: 'local' },
    { title: 'UNLOVED',                               short: 'UNLOVED',            group: 'Инди • Хоррор',       img: steamImg(267560),                 tags: ['Хоррор', 'Шутер', 'Roguelike'],                   opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'The Outlast Trials',                    short: 'Outlast Trials',     group: 'Инди • Хоррор',       img: steamImg(1304930),                tags: ['Хоррор', 'Кооп', 'Выживание'],                   opts: ['online'],         source: 'local' },
    { title: 'Hello Neighbor',                        short: 'Hello Neighbor',     group: 'Инди • Хоррор',       img: steamImg(730490),                 tags: ['Хоррор', 'Стелс', 'Головоломка'],                opts: [],                 source: 'local' },
    { title: 'Secret Neighbor',                       short: 'Secret Neighbor',    group: 'Инди • Хоррор',       img: steamImg(1053830),                tags: ['Хоррор', 'Мультиплеер', 'Кооп'],                 opts: ['online'],         source: 'local' },
    { title: 'PANICORE',                              short: 'PANICORE',           group: 'Инди • Хоррор',       img: steamImg(2289920),                tags: ['Хоррор', 'Кооп'],                                opts: ['online'],         source: 'local' },
    { title: 'Nuclear Nightmare',                     short: 'Nuclear Nightmare',  group: 'Инди • Хоррор',       img: steamImg(1875560),                tags: ['Хоррор', 'Выживание'],                           opts: [],                 source: 'local' },
    { title: 'LIMBO',                                 short: 'LIMBO',              group: 'Инди • Хоррор',       img: steamImg(48000),                  tags: ['Платформер', 'Атмосфера', 'Головоломка'],        opts: [],                 source: 'local' },
    { title: 'Buckshot Roulette',                     short: 'Buckshot Roulette',  group: 'Инди • Хоррор',       img: steamImg(2835570),                tags: ['Хоррор', 'Необычное', 'Казуальное'],             opts: [],                 source: 'local' },
    { title: 'Little Nightmares Enhanced Edition',    short: 'LN Enhanced',        group: 'Инди • Хоррор',       img: steamImg(860510),   hasDlc: true,  tags: ['Хоррор', 'Платформер', 'Атмосфера'],            opts: ['dlc'],            source: 'local' ,  marme1adker: true },

    // ── Roguelike ────────────────────────────────────────────────
    { title: 'Hades',                                 short: 'Hades',              group: 'Инди • Roguelike',    img: steamImg(1145360),                tags: ['Roguelike', 'Экшн', 'Сюжет'],                     opts: [],                 source: 'steam' },
    { title: 'Hades II',                              short: 'Hades II',           group: 'Инди • Roguelike',    img: steamImg(1145350),                tags: ['Roguelike', 'Экшн'],                              opts: [],                 source: 'steam' },
    { title: 'Dead Cells',                            short: 'Dead Cells',         group: 'Инди • Roguelike',    img: steamImg(588650),   hasDlc: true,  tags: ['Roguelike', 'Метроидвания', 'Хардкор'],            opts: ['dlc'],            source: 'local' ,  marme1adker: true },
    { title: 'Balatro',                               short: 'Balatro',            group: 'Инди • Roguelike',    img: steamImg(2379780),                tags: ['Roguelike', 'Карточная'],                         opts: [],                 source: 'steam' },
    { title: 'Slay the Spire',                        short: 'StS',                group: 'Инди • Roguelike',    img: steamImg(646570),   hasDlc: true,  tags: ['Roguelike', 'Карточная'],                         opts: ['dlc'],            source: 'steam' },
    { title: 'R.E.P.O.',                              short: 'R.E.P.O.',           group: 'Инди • Roguelike',    img: steamImg(3241660),                tags: ['Roguelike', 'Кооп', 'Хоррор'],                    opts: ['online'],         source: 'local' ,  marme1adker: true },

    // ── Platformer ───────────────────────────────────────────────
    { title: 'Hollow Knight',                         short: 'Hollow Knight',      group: 'Инди • Платформер',   img: steamImg(367520),                 tags: ['Метроидвания', 'Хардкор', 'Атмосфера'],           opts: [],                 source: 'local' },
    { title: 'Celeste',                               short: 'Celeste',            group: 'Инди • Платформер',   img: steamImg(504230),                 tags: ['Платформер', 'Хардкор', 'Сюжет'],                 opts: [],                 source: 'steam' },
    { title: 'Cuphead',                               short: 'Cuphead',            group: 'Инди • Платформер',   img: steamImg(268910),   hasDlc: true,  tags: ['Платформер', 'Хардкор', 'Кооп'],                  opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Geometry Dash',                         short: 'GD',                 group: 'Инди • Платформер',   img: steamImg(322170),                 tags: ['Платформер', 'Ритм', 'Хардкор'],                  opts: [],                 source: 'local' },
    { title: 'Broforce',                              short: 'Broforce',           group: 'Инди • Платформер',   img: steamImg(274190),                 tags: ['Платформер', 'Кооп', 'Юмор'],                     opts: ['online'],         source: 'local' },
    { title: 'Bully: Scholarship Edition',            short: 'Bully',              group: 'Инди • Платформер',   img: steamImg(12200),                  tags: ['Открытый мир', 'Экшн', 'Классика'],              opts: [],                 source: 'local' },
    { title: 'Webbed',                                short: 'Webbed',             group: 'Инди • Платформер',   img: steamImg(1390350),                tags: ['Платформер', 'Инди', 'Расслабляющее'],           opts: [],                 source: 'local' },
    { title: 'Super Bunny Man',                       short: 'Super Bunny Man',    group: 'Инди • Платформер',   img: steamImg(902490),                 tags: ['Платформер', 'Кооп', 'Юмор'],                   opts: ['online'],         source: 'local' },
    { title: 'Clustertruck',                          short: 'Clustertruck',       group: 'Инди • Платформер',   img: steamImg(427550),                 tags: ['Платформер', 'Физика', 'Хардкор'],               opts: [],                 source: 'local' },
    { title: 'Black Mesa',                            short: 'Black Mesa',         group: 'Инди • Платформер',   img: steamImg(362890),   hasDlc: true,  tags: ['Шутер', 'Классика', 'Сюжет'],                   opts: ['dlc'],            source: 'local' },
    { title: 'Punch Club',                            short: 'Punch Club',         group: 'Инди • Платформер',   img: steamImg(394730),                 tags: ['Симулятор', 'RPG', 'Пиксели'],                  opts: [],                 source: 'local' },

    // ── RPG ──────────────────────────────────────────────────────
    { title: 'Stardew Valley',                        short: 'Stardew',            group: 'Инди • RPG',          img: steamImg(413150),                 tags: ['Фарминг', 'Расслабляющее', 'Кооп'],               opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'Undertale',                             short: 'Undertale',          group: 'Инди • RPG',          img: steamImg(391540),                 tags: ['RPG', 'Сюжет', 'Необычное'],                      opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Disco Elysium',                         short: 'Disco Elysium',      group: 'Инди • RPG',          img: steamImg(632470),   hasDlc: true,  tags: ['RPG', 'Сюжет', 'Детектив'],                       opts: ['dlc', 'ru'],      source: 'steam' },
    { title: 'Outer Wilds',                           short: 'Outer Wilds',        group: 'Инди • RPG',          img: steamImg(753640),   hasDlc: true,  tags: ['Приключение', 'Исследование', 'Сюжет'],           opts: ['dlc'],            source: 'steam' },
    { title: 'Kingdom Come: Deliverance',             short: 'KCD',                group: 'Инди • RPG',          img: steamImg(379430),   hasDlc: true,  tags: ['RPG', 'История', 'Реализм', 'Средневековье'],     opts: ['dlc'],            source: 'local' },
    { title: 'Frostpunk',                             short: 'Frostpunk',          group: 'Инди • RPG',          img: steamImg(323190),   hasDlc: true,  tags: ['Стратегия', 'Выживание', 'Атмосфера'],            opts: ['dlc'],            source: 'local' },
    { title: 'Life is Strange',                       short: 'LiS',                group: 'Инди • RPG',          img: steamImg(319630),                 tags: ['Сюжет', 'Приключение', 'Драма'],                  opts: [],                 source: 'local' },
    { title: 'Life is Strange 2',                     short: 'LiS 2',              group: 'Инди • RPG',          img: steamImg(532210),                 tags: ['Сюжет', 'Приключение', 'Драма'],                  opts: [],                 source: 'local' },
    { title: 'Slime Rancher',                         short: 'Slime Rancher',      group: 'Инди • RPG',          img: steamImg(433340),                 tags: ['Фарминг', 'Расслабляющее', 'Милое'],              opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Slime Rancher 2',                       short: 'Slime Rancher 2',    group: 'Инди • RPG',          img: steamImg(1657630),                tags: ['Фарминг', 'Расслабляющее', 'Милое'],              opts: [],                 source: 'local' },
    { title: 'The Wolf Among Us',                     short: 'Wolf Among Us',      group: 'Инди • RPG',          img: steamImg(250320),                 tags: ['Сюжет', 'Интерактивное кино', 'Детектив'],       opts: [],                 source: 'local' },
    { title: 'Papers, Please',                        short: 'Papers Please',      group: 'Инди • RPG',          img: steamImg(239030),                 tags: ['Инди', 'Необычное', 'Атмосфера', 'Сюжет'],      opts: [],                 source: 'local' },
    { title: 'Firewatch',                             short: 'Firewatch',          group: 'Инди • RPG',          img: steamImg(383870),                 tags: ['Приключение', 'Атмосфера', 'Сюжет'],             opts: [],                 source: 'local' },
    { title: 'Beholder',                              short: 'Beholder',           group: 'Инди • RPG',          img: steamImg(475550),   hasDlc: true,  tags: ['Стратегия', 'Сюжет', 'Атмосфера', 'Необычное'], opts: ['dlc'],            source: 'local' },
    { title: 'Plague Inc: Evolved',                   short: 'Plague Inc',         group: 'Инди • RPG',          img: steamImg(246620),                 tags: ['Стратегия', 'Необычное', 'Симулятор'],           opts: [],                 source: 'local' },

    // ── Co-op ────────────────────────────────────────────────────
    { title: 'Deep Rock Galactic',                    short: 'DRG',                group: 'Инди • Кооп',         img: steamImg(548430),   hasDlc: true,  tags: ['Кооп', 'Шутер', 'Подземелье'],                    opts: ['dlc', 'online'],  source: 'steam' },
    { title: 'It Takes Two',                          short: 'It Takes Two',       group: 'Инди • Кооп',         img: steamImg(1426210),                tags: ['Кооп', 'Платформер', 'Сюжет'],                    opts: ['online'],         source: 'steam' },
    { title: 'Among Us',                              short: 'Among Us',           group: 'Инди • Кооп',         img: steamImg(945360),                 tags: ['Мультиплеер', 'Для всех', 'Казуальное'],           opts: ['online'],         source: 'local' },
    { title: "Don't Starve Together",                 short: 'DST',                group: 'Инди • Кооп',         img: steamImg(322330),   hasDlc: true,  tags: ['Выживание', 'Кооп', 'Хардкор'],                   opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Killing Floor',                         short: 'KF1',                group: 'Инди • Кооп',         img: steamImg(1250),                   tags: ['Зомби', 'Кооп', 'Шутер'],                         opts: ['online'],         source: 'local' },
    { title: 'Warhammer: Vermintide 2',               short: 'V2',                 group: 'Инди • Кооп',         img: steamImg(552500),   hasDlc: true,  tags: ['Кооп', 'Фэнтези', 'Экшн'],                       opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'Magicka',                               short: 'Magicka',            group: 'Инди • Кооп',         img: steamImg(42910),    hasDlc: true,  tags: ['Кооп', 'Магия', 'Юмор'],                         opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Iron Harvest',                          short: 'Iron Harvest',       group: 'Инди • Кооп',         img: steamImg(1128860),  hasDlc: true,  tags: ['Стратегия', 'Кооп', 'ВМВ'],                       opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Company of Heroes 2',                   short: 'CoH2',               group: 'Инди • Кооп',         img: steamImg(231430),   hasDlc: true,  tags: ['Стратегия', 'ВМВ', 'Кооп'],                       opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Friday the 13th',                       short: 'F13',                group: 'Инди • Кооп',         img: steamImg(438740),                 tags: ['Хоррор', 'Мультиплеер', 'Асимметричный'],         opts: ['online'],         source: 'local' },
    { title: 'PAYDAY 2',                              short: 'PD2',                group: 'Инди • Кооп',         img: steamImg(218620),   hasDlc: true,  tags: ['Шутер', 'Кооп', 'Ограбление'],                    opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'Human Fall Flat',                       short: 'Human Fall Flat',    group: 'Инди • Кооп',         img: steamImg(477160),   hasDlc: true,  tags: ['Головоломка', 'Кооп', 'Физика', 'Юмор'],        opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: "Who's Your Daddy?!",                    short: "Who's Your Daddy",   group: 'Инди • Кооп',         img: steamImg(427730),                 tags: ['Кооп', 'Юмор', 'Необычное'],                    opts: ['online'],         source: 'local' },
    { title: 'Clone Drone in the Danger Zone',        short: 'Clone Drone',        group: 'Инди • Кооп',         img: steamImg(597170),                 tags: ['Экшн', 'Кооп', 'Roguelike'],                    opts: ['online'],         source: 'local' },
    { title: 'Tomato Jones 2',                        short: 'Tomato Jones 2',     group: 'Инди • Кооп',         img: steamImg(2383280),                tags: ['Платформер', 'Кооп'],                            opts: ['online'],         source: 'local' },
    { title: 'Choo-Choose',                           short: 'Choo-Choose',        group: 'Инди • Кооп',         img: steamImg(1271690),                tags: ['Ужастик', 'Кооп', 'Необычное'],                  opts: ['online'],         source: 'local' },
    { title: 'DeathComing',                           short: 'DeathComing',        group: 'Инди • Кооп',         img: steamImg(811780),                 tags: ['Головоломка', 'Необычное', 'Пиксели'],           opts: [],                 source: 'local' },

    // ── Simulation / Casual ───────────────────────────────────────
    { title: 'Schedule I',                            short: 'Schedule I',         group: 'Инди • Симулятор',    img: steamImg(3164500),                tags: ['Симулятор', 'Открытый мир', 'Бизнес'],            opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'Teardown',                              short: 'Teardown',           group: 'Инди • Симулятор',    img: steamImg(1167630),  hasDlc: true,  tags: ['Симулятор', 'Разрушение', 'Физика', 'Песочница'], opts: ['dlc'],            source: 'local' },
    { title: 'People Playground',                     short: 'People PG',          group: 'Инди • Симулятор',    img: steamImg(1118200),                tags: ['Симулятор', 'Физика', 'Песочница'],               opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Wallpaper Engine',                      short: 'Wallpaper Engine',   group: 'Инди • Симулятор',    img: steamImg(431960),                 tags: ['Утилита', 'Кастомизация'],                        opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Car Mechanic Simulator 2018',           short: 'CMS 2018',           group: 'Инди • Симулятор',    img: steamImg(754920),   hasDlc: true,  tags: ['Симулятор', 'Машины'],                            opts: ['dlc'],            source: 'local' },
    { title: 'Car Dealer Simulator',                  short: 'Car Dealer',         group: 'Инди • Симулятор',    img: steamImg(1452280),                tags: ['Симулятор', 'Бизнес'],                            opts: [],                 source: 'local' },
    { title: '911 Operator',                          short: '911 Operator',       group: 'Инди • Симулятор',    img: steamImg(503560),   hasDlc: true,  tags: ['Симулятор', 'Стратегия'],                         opts: ['dlc'],            source: 'local' },
    { title: 'Totally Accurate Battle Simulator',     short: 'TABS',               group: 'Инди • Симулятор',    img: steamImg(508440),                 tags: ['Симулятор', 'Физика', 'Юмор', 'Для всех'],      opts: ['online'],         source: 'local' },
    { title: 'WorldBox - God Simulator',              short: 'WorldBox',           group: 'Инди • Симулятор',    img: steamImg(1206560),                tags: ['Симулятор', 'Песочница', 'Стратегия'],           opts: [],                 source: 'local' },
    { title: 'Goat Simulator',                        short: 'Goat Sim',           group: 'Инди • Симулятор',    img: steamImg(265930),   hasDlc: true,  tags: ['Симулятор', 'Юмор', 'Необычное'],                opts: ['dlc'],            source: 'local' },
    { title: 'Spore',                                 short: 'Spore',              group: 'Инди • Симулятор',    img: steamImg(17390),    hasDlc: true,  tags: ['Симулятор', 'Песочница', 'Стратегия'],           opts: ['dlc'],            source: 'local' },
    { title: 'Cities: Skylines',                      short: 'Cities Skylines',    group: 'Инди • Симулятор',    img: steamImg(255710),   hasDlc: true,  tags: ['Симулятор', 'Строительство', 'Стратегия'],       opts: ['dlc'],            source: 'local' },
    { title: 'Poly Bridge',                           short: 'Poly Bridge',        group: 'Инди • Симулятор',    img: steamImg(367450),                 tags: ['Головоломка', 'Строительство', 'Физика'],        opts: [],                 source: 'local' },
    { title: 'Sand:box',                              short: 'Sandbox',            group: 'Инди • Симулятор',    img: steamImg(1003650),                tags: ['Симулятор', 'Физика', 'Песочница'],              opts: [],                 source: 'local' },
    { title: 'Happy Room',                            short: 'Happy Room',         group: 'Инди • Симулятор',    img: steamImg(415280),                 tags: ['Симулятор', 'Физика', 'Юмор'],                   opts: [],                 source: 'local' },
    { title: 'theHunter: Call of the Wild',           short: 'theHunter',          group: 'Инди • Симулятор',    img: steamImg(518790),   hasDlc: true,  tags: ['Симулятор', 'Охота', 'Открытый мир'],            opts: ['dlc'],            source: 'local' },
    { title: 'Симулятор чушпана',                     short: 'Симулятор чушпана',  group: 'Инди • Симулятор',    img: steamImg(2755330),                tags: ['Симулятор', 'Инди', 'Необычное'],                opts: ['ru'],             source: 'local' },

    // ── Strategy ─────────────────────────────────────────────────
    { title: 'Spellforce 3',                          short: 'Spellforce 3',       group: 'Инди • Стратегия',    img: steamImg(263380),   hasDlc: true,  tags: ['Стратегия', 'RPG', 'Фэнтези', 'Кооп'],            opts: ['dlc', 'online'],  source: 'local' },
    { title: 'For the King',                          short: 'For the King',       group: 'Инди • Стратегия',    img: steamImg(527230),   hasDlc: true,  tags: ['Стратегия', 'Roguelike', 'Кооп', 'Фэнтези'],      opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Jagged Alliance Gold',                  short: 'JA Gold',            group: 'Инди • Стратегия',    img: steamImg(248950),                 tags: ['Стратегия', 'Тактика', 'Классика'],               opts: [],                 source: 'local' },
    { title: 'CONTROL',                               short: 'Control',            group: 'Инди • Стратегия',    img: steamImg(870780),   hasDlc: true,  tags: ['Экшн', 'Сюжет', 'Фантастика'],                    opts: ['dlc'],            source: 'local' },

    // ── Action ───────────────────────────────────────────────────
    { title: 'SUPERHOT',                              short: 'SUPERHOT',           group: 'Инди • Экшн',         img: steamImg(322500),                 tags: ['Шутер', 'Головоломка', 'Необычное'],             opts: [],                 source: 'local' },
    { title: 'Devil May Cry 5',                       short: 'DMC5',               group: 'Инди • Экшн',         img: steamImg(601150),   hasDlc: true,  tags: ['Экшн', 'Слэшер', 'Хардкор'],                    opts: ['dlc'],            source: 'local' ,  marme1adker: true },
    { title: 'Saints Row: The Third',                 short: 'Saints Row 3',       group: 'Инди • Экшн',         img: steamImg(55230),    hasDlc: true,  tags: ['Открытый мир', 'Экшн', 'Юмор'],                 opts: ['dlc'],            source: 'local' },
    { title: 'Sniper Elite 4',                        short: 'Sniper Elite 4',     group: 'Инди • Экшн',         img: steamImg(314800),   hasDlc: true,  tags: ['Шутер', 'Стелс', 'Снайпер'],                    opts: ['dlc'],            source: 'local' },
    { title: 'Risk of Rain 2',                        short: 'RoR2',               group: 'Инди • Экшн',         img: steamImg(632360),   hasDlc: true,  tags: ['Roguelike', 'Кооп', 'Шутер'],                   opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: 'Dark Sector',                           short: 'Dark Sector',        group: 'Инди • Экшн',         img: steamImg(10110),                  tags: ['Экшн', 'Шутер', 'Сюжет'],                       opts: [],                 source: 'local' },
    { title: 'Stray',                                 short: 'Stray',              group: 'Инди • Экшн',         img: steamImg(1332010),                tags: ['Приключение', 'Атмосфера', 'Необычное'],         opts: [],                 source: 'local' },
    { title: "JoJo's Bizarre Adventure: All-Star Battle R", short: 'JoJo ASBR',   group: 'Инди • Экшн',          img: steamImg(1372110),  hasDlc: true,  tags: ['Файтинг', 'Аниме', 'Мультиплеер'],              opts: ['dlc', 'online'],  source: 'local' },
    { title: 'РУСЫ ПРОТИВ ЯЩЕРОВ',                    short: 'Русы vs Ящеры',      group: 'Инди • Экшн',         img: steamImg(2532550),                tags: ['Экшн', 'Инди', 'Необычное'],                     opts: ['ru'],             source: 'local',  marme1adker: true },

    // ── Misc Indie ───────────────────────────────────────────────
    { title: 'Starbound',                             short: 'Starbound',          group: 'Инди • Разное',       img: steamImg(211820),                 tags: ['Выживание', 'Крафт', 'Кооп', 'Фантастика'],       opts: ['online'],         source: 'local' },
    { title: 'Sunless Sea',                           short: 'Sunless Sea',        group: 'Инди • Разное',       img: steamImg(304650),                 tags: ['RPG', 'Атмосфера', 'Необычное'],                  opts: [],                 source: 'local' },
    { title: 'Titan Quest Anniversary Edition',       short: 'Titan Quest',        group: 'Инди • Разное',       img: steamImg(475150),   hasDlc: true,  tags: ['RPG', 'Экшн', 'Мифология', 'Кооп'],               opts: ['dlc', 'online'],  source: 'local' },
    { title: 'Tomb Raider',                           short: 'Tomb Raider',        group: 'Инди • Разное',       img: steamImg(203160),   hasDlc: true,  tags: ['Экшн', 'Приключение', 'Открытый мир'],            opts: ['dlc'],            source: 'local' },
    { title: 'Torchlight II',                         short: 'Torchlight 2',       group: 'Инди • Разное',       img: steamImg(200710),                 tags: ['RPG', 'Экшн', 'Кооп', 'Лут'],                     opts: ['online'],         source: 'local' },
    { title: 'Risen 2 - Dark Waters',                 short: 'Risen 2',            group: 'Инди • Разное',       img: steamImg(40390),    hasDlc: true,  tags: ['RPG', 'Приключение', 'Пираты'],                   opts: ['dlc'],            source: 'local' },
    { title: 'The Cave',                              short: 'The Cave',           group: 'Инди • Разное',       img: steamImg(221810),                 tags: ['Платформер', 'Головоломка', 'Кооп'],               opts: ['online'],         source: 'local' },
    { title: 'The Stanley Parable',                   short: 'Stanley Parable',    group: 'Инди • Разное',       img: steamImg(221910),                 tags: ['Необычное', 'Сюжет', 'Юмор'],                     opts: [],                 source: 'local' },
    { title: 'The Walking Dead: The Telltale Definitive Series', short: 'TWD Telltale', group: 'Инди • Разное',  img: steamImg(1449690),                tags: ['Сюжет', 'Интерактивное кино', 'Зомби'],           opts: [],                 source: 'local' },
    { title: 'Hardland',                              short: 'Hardland',           group: 'Инди • Разное',       img: steamImg(314990),                 tags: ['RPG', 'Приключение', 'Открытый мир'],             opts: [],                 source: 'local' },
    { title: 'Drawful 2',                             short: 'Drawful 2',          group: 'Инди • Разное',       img: steamImg(442070),                 tags: ['Казуальное', 'Для всех', 'Кооп'],                 opts: ['online'],         source: 'local' ,  marme1adker: true },
    { title: 'Batman: Arkham City GOTY',              short: 'Batman AC',          group: 'Инди • Разное',       img: steamImg(200260),   hasDlc: true,  tags: ['Экшн', 'Стелс', 'Супергерой'],                   opts: ['dlc'],            source: 'local' },
    { title: 'Batman: Arkham Origins',                short: 'Batman AO',          group: 'Инди • Разное',       img: steamImg(209000),   hasDlc: true,  tags: ['Экшн', 'Стелс', 'Супергерой'],                   opts: ['dlc'],            source: 'local' },
    { title: 'Serious Sam Fusion 2017',               short: 'SS Fusion',          group: 'Инди • Разное',       img: steamImg(564310),   hasDlc: true,  tags: ['Шутер', 'Кооп', 'Юмор'],                         opts: ['dlc', 'online'],  source: 'local' },
    { title: 'STAR WARS Jedi Knight: Jedi Academy',   short: 'Jedi Academy',       group: 'Инди • Разное',       img: steamImg(6020),                   tags: ['Экшн', 'Классика', 'Шутер'],                      opts: [],                 source: 'local' },
    { title: 'Darkness II',                           short: 'Darkness 2',         group: 'Инди • Разное',       img: steamImg(67895),                  tags: ['Шутер', 'Экшн', 'Сюжет'],                        opts: [],                 source: 'local' },
    { title: 'POSTAL 2',                              short: 'Postal 2',           group: 'Инди • Разное',       img: steamImg(223470),                 tags: ['Шутер', 'Открытый мир', 'Юмор', 'Безумие'],      opts: [],                 source: 'local' },
    { title: 'Bet on Soldier',                        short: 'Bet on Soldier',     group: 'Инди • Разное',       img: steamImg(3210),                   tags: ['Шутер', 'Классика'],                              opts: [],                 source: 'local' },
    { title: 'Intravenous',                           short: 'Intravenous',        group: 'Инди • Разное',       img: steamImg(1012510),                tags: ['Стелс', 'Шутер', 'Хардкор'],                      opts: [],                 source: 'local' },
    { title: 'Despotism 3k',                          short: 'Despotism 3k',       group: 'Инди • Разное',       img: steamImg(698920),                 tags: ['Стратегия', 'Необычное', 'Юмор'],                 opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Apewar',                                short: 'Apewar',             group: 'Инди • Разное',       img: steamImg(1574940),                tags: ['Шутер', 'Аркада'],                                opts: [],                 source: 'local' },
    { title: 'Pankapu',                               short: 'Pankapu',            group: 'Инди • Разное',       img: steamImg(523020),                 tags: ['Платформер', 'Сюжет'],                            opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Machinika Museum',                      short: 'Machinika',          group: 'Инди • Разное',       img: steamImg(1507210),                tags: ['Головоломка', 'Расслабляющее', 'Необычное'],      opts: [],                 source: 'local' ,  marme1adker: true },
    { title: '100% Orange Juice',                     short: '100% OJ',            group: 'Инди • Разное',       img: steamImg(282800),   hasDlc: true,  tags: ['Настольная', 'Кооп', 'Казуальное'],               opts: ['dlc', 'online'],  source: 'local' ,  marme1adker: true },
    { title: "Cakey's Twisted Bakery",                short: "Cakey's Bakery",     group: 'Инди • Разное',       img: steamImg(1930730),                tags: ['Казуальное', 'Хоррор'],                           opts: [],                 source: 'local' },
    { title: 'Distant Space',                         short: 'Distant Space',      group: 'Инди • Разное',       img: steamImg(460330),                 tags: ['Шутер', 'Фантастика'],                            opts: [],                 source: 'local' },
    { title: 'Distant Space 2',                       short: 'Distant Space 2',    group: 'Инди • Разное',       img: steamImg(1035360),                tags: ['Шутер', 'Фантастика'],                            opts: [],                 source: 'local' ,  marme1adker: true },
    { title: 'Weapon of Choice',                      short: 'Weapon of Choice',   group: 'Инди • Разное',       img: steamImg(288550),                 tags: ['Шутер', 'Аркада', 'Классика'],                    opts: [],                 source: 'local' },
    { title: 'MyVoiceZoo',                            short: 'MyVoiceZoo',         group: 'Инди • Разное',       img: steamImg(2140290),                tags: ['Казуальное', 'Для всех'],                        opts: [],                 source: 'local' },
    { title: 'Ben and Ed',                            short: 'Ben and Ed',         group: 'Инди • Разное',       img: steamImg(321180),                 tags: ['Платформер', 'Хоррор', 'Юмор'],                 opts: [],                 source: 'local' },
    { title: 'Party Hard 2',                          short: 'Party Hard 2',       group: 'Инди • Разное',       img: steamImg(621060),                 tags: ['Стелс', 'Пиксели', 'Необычное'],                opts: [],                 source: 'local' },
    { title: 'Cult of the Lamb',                      short: 'Cult of the Lamb',   group: 'Инди • Разное',       img: steamImg(1313140),  hasDlc: true,  tags: ['Roguelike', 'Необычное', 'Управление'],         opts: ['dlc'],            source: 'local' },
    { title: 'Plants vs. Zombies: Game of the Year',  short: 'PvZ GOTY',           group: 'Инди • Разное',       img: steamImg(3590),                   tags: ['Стратегия', 'Казуальное', 'Для всех'],          opts: [],                 source: 'local' },
    { title: '60 Seconds! Reatomized',                short: '60 Seconds',         group: 'Инди • Разное',       img: steamImg(1012880),                tags: ['Выживание', 'Необычное', 'Юмор'],               opts: [],                 source: 'local' },
    { title: 'Barro 22',                              short: 'Barro 22',           group: 'Инди • Разное',       img: steamImg(1644380),                tags: ['Гонки', 'Аркада'],                              opts: [],                 source: 'local' },
    { title: 'Jacksmith: Weapons and Warriors',       short: 'Jacksmith',          group: 'Инди • Разное',       img: steamImg(2277290),                tags: ['Казуальное', 'Необычное'],                      opts: [],                 source: 'local' },
    { title: '12 is Better Than 6',                   short: '12 is Better',       group: 'Инди • Разное',       img: steamImg(410110),                 tags: ['Шутер', 'Пиксели', 'Экшн'],                     opts: [],                 source: 'local' },
    { title: 'The Binding of Isaac',                  short: 'BoI',                group: 'Инди • Разное',       img: steamImg(113200),                 tags: ['Roguelike', 'Хоррор', 'Хардкор'],               opts: [],                 source: 'local' },
    { title: 'The Binding of Isaac: Rebirth',         short: 'BoI Rebirth',        group: 'Инди • Разное',       img: steamImg(250900),   hasDlc: true,  tags: ['Roguelike', 'Хоррор', 'Хардкор'],               opts: ['dlc'],            source: 'local' },
    { title: 'Бройлеры',                              short: 'Бройлеры',           group: 'Инди • Разное',       img: steamImg(1562780),                tags: ['Инди', 'Необычное'],                             opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'Мистер Фурри: Горячие Мускулы',         short: 'Мистер Фурри',       group: 'Инди • Разное',       img: steamImg(1578220),                tags: ['Инди', 'Необычное'],                             opts: ['ru'],             source: 'local' },

    // ── Metro series ─────────────────────────────────────────────
    { title: 'Metro 2033',                            short: 'Metro 2033',         group: 'Metro series',        img: steamImg(43110),                  tags: ['Шутер', 'Постапокалипсис', 'Атмосфера', 'Хоррор'], opts: ['ru'],            source: 'local' },
    { title: 'Metro 2033 Redux',                      short: 'Metro 2033 Redux',   group: 'Metro series',        img: steamImg(286690),                 tags: ['Шутер', 'Постапокалипсис', 'Атмосфера'],          opts: ['ru'],             source: 'local' ,  marme1adker: true },
    { title: 'Metro: Last Light',                     short: 'Metro LL',           group: 'Metro series',        img: steamImg(239030),                 tags: ['Шутер', 'Постапокалипсис', 'Атмосфера', 'Хоррор'], opts: ['ru'],            source: 'local' },
    { title: 'Metro Exodus',                          short: 'Metro Exodus',       group: 'Metro series',        img: steamImg(412020),   hasDlc: true,  tags: ['Шутер', 'Постапокалипсис', 'Открытый мир'],       opts: ['dlc', 'ru'],      source: 'local' ,  marme1adker: true },
    { title: 'Metro Exodus Enhanced Edition',         short: 'Metro Exodus EE',    group: 'Metro series',        img: steamImg(1449560),  hasDlc: true,  tags: ['Шутер', 'Постапокалипсис', 'Открытый мир'],       opts: ['dlc', 'ru'],      source: 'local' ,  marme1adker: true },

    // ── Hitman series ─────────────────────────────────────────────
    { title: 'HITMAN World of Assassination',         short: 'Hitman WOA',         group: 'Hitman series',       img: steamImg(1659040),  hasDlc: true,  tags: ['Стелс', 'Экшн', 'Сюжет'],                        opts: ['dlc'],            source: 'local' },
    { title: 'Hitman: Absolution',                    short: 'Hitman Absolution',  group: 'Hitman series',       img: steamImg(203140),                 tags: ['Стелс', 'Экшн', 'Сюжет'],                        opts: [],                 source: 'local' },
    { title: 'Hitman: Sniper Challenge',              short: 'Hitman Sniper',      group: 'Hitman series',       img: steamImg(205930),                 tags: ['Стелс', 'Снайпер'],                               opts: [],                 source: 'local' },

    // ── Hotline Miami ─────────────────────────────────────────────
    { title: 'Hotline Miami',                         short: 'Hotline Miami 1',    group: 'Hotline Miami',       img: steamImg(219150),                 tags: ['Экшн', 'Хардкор', 'Пиксели', 'Атмосфера'],       opts: [],                 source: 'local' },
    { title: 'Hotline Miami 2: Wrong Number',         short: 'Hotline Miami 2',    group: 'Hotline Miami',       img: steamImg(274170),                 tags: ['Экшн', 'Хардкор', 'Пиксели', 'Атмосфера'],       opts: [],                 source: 'local' },

    // ── Batman Arkham ─────────────────────────────────────────────
    { title: 'Batman: Arkham Asylum GOTY Edition',    short: 'Batman AA',          group: 'Batman Arkham',       img: steamImg(35140),    hasDlc: true,  tags: ['Экшн', 'Стелс', 'Супергерой'],                   opts: ['dlc'],            source: 'local' },
    { title: 'Batman: Arkham Knight',                 short: 'Batman AK',          group: 'Batman Arkham',       img: steamImg(208650),   hasDlc: true,  tags: ['Экшн', 'Стелс', 'Супергерой', 'Открытый мир'],  opts: ['dlc'],            source: 'local' },

    // ── Resident Evil ─────────────────────────────────────────────
    { title: 'Resident Evil 7 Biohazard',             short: 'RE7',                group: 'Resident Evil',       img: steamImg(418370),   hasDlc: true,  tags: ['Хоррор', 'Выживание', 'Сюжет'],                  opts: ['dlc'],            source: 'local' },
    { title: 'Resident Evil Village',                 short: 'RE Village',         group: 'Resident Evil',       img: steamImg(1196590),  hasDlc: true,  tags: ['Хоррор', 'Выживание', 'Сюжет'],                  opts: ['dlc'],            source: 'local' },

    // ── BioShock ──────────────────────────────────────────────────
    { title: 'BioShock 2',                            short: 'BioShock 2',         group: 'BioShock',            img: steamImg(8850),     hasDlc: true,  tags: ['Шутер', 'Сюжет', 'Фантастика', 'Атмосфера'],     opts: ['dlc'],            source: 'local' },
    { title: 'BioShock 2 Remastered',                 short: 'BioShock 2 R',       group: 'BioShock',            img: steamImg(409720),   hasDlc: true,  tags: ['Шутер', 'Сюжет', 'Фантастика', 'Атмосфера'],     opts: ['dlc'],            source: 'local' },

    // ── Wolfenstein ───────────────────────────────────────────────
    { title: 'Wolfenstein II: The New Colossus',      short: 'Wolfenstein II',     group: 'Wolfenstein',         img: steamImg(612880),   hasDlc: true,  tags: ['Шутер', 'Сюжет', 'Экшн'],                        opts: ['dlc'],            source: 'local' },
    { title: 'Wolfenstein: The Old Blood',            short: 'Wolfenstein TOB',    group: 'Wolfenstein',         img: steamImg(350080),                 tags: ['Шутер', 'Экшн'],                                  opts: [],                 source: 'local' },

    // ── The Dark Pictures ─────────────────────────────────────────
    { title: 'The Dark Pictures Anthology: Man of Medan',  short: 'Man of Medan',  group: 'The Dark Pictures',   img: steamImg(960090),                tags: ['Хоррор', 'Сюжет', 'Интерактивное кино', 'Кооп'],  opts: ['online'],         source: 'local' },
    { title: 'The Dark Pictures Anthology: Little Hope',   short: 'Little Hope',   group: 'The Dark Pictures',   img: steamImg(1286840),               tags: ['Хоррор', 'Сюжет', 'Интерактивное кино'],          opts: [],                 source: 'local' },

    // ── Choice of Life ────────────────────────────────────────────
    { title: 'Choice of Life: Middle Ages',           short: 'CoL Middle Ages',    group: 'Choice of Life',      img: steamImg(1123990),                tags: ['Стратегия', 'Пиксели', 'Необычное'],              opts: [],                 source: 'local' },
    { title: 'Choice of Life: Middle Ages 2',         short: 'CoL Middle Ages 2',  group: 'Choice of Life',      img: steamImg(1781620),                tags: ['Стратегия', 'Пиксели', 'Необычное'],              opts: [],                 source: 'local' },
    { title: 'Choice of Life: Wild Islands',          short: 'CoL Wild Islands',   group: 'Choice of Life',      img: steamImg(2139640),                tags: ['Стратегия', 'Пиксели', 'Необычное'],              opts: [],                 source: 'local' },

    // ── LEGO ──────────────────────────────────────────────────────
    { title: 'The LEGO Movie - Videogame',            short: 'LEGO Movie 1',       group: 'LEGO',                img: steamImg(267530),                 tags: ['Платформер', 'Для всех', 'Кооп'],                 opts: ['online'],         source: 'local' },
    { title: 'The LEGO Movie 2 - The Second Part',    short: 'LEGO Movie 2',       group: 'LEGO',                img: steamImg(787460),                 tags: ['Платформер', 'Для всех', 'Кооп'],                 opts: ['online'],         source: 'local' },

    // ── FlatOut series ────────────────────────────────────────────
    { title: 'FlatOut',                               short: 'FlatOut 1',          group: 'FlatOut',             img: steamImg(2990),                   tags: ['Гонки', 'Аркада', 'Классика'],                   opts: [],                 source: 'local' },
    { title: 'FlatOut: Ultimate Carnage',             short: 'FlatOut UC',         group: 'FlatOut',             img: steamImg(12830),                  tags: ['Гонки', 'Аркада', 'Разрушение'],                 opts: [],                 source: 'local' },
    { title: 'FlatOut 3: Chaos & Destruction',        short: 'FlatOut 3',          group: 'FlatOut',             img: steamImg(222850),                 tags: ['Гонки', 'Аркада'],                               opts: [],                 source: 'local' },

    // ── Remedy ───────────────────────────────────────────────────
    { title: 'Alan Wake',                             short: 'Alan Wake',          group: 'Remedy',              img: steamImg(108710),   hasDlc: true,  tags: ['Хоррор', 'Экшн', 'Сюжет', 'Атмосфера'],         opts: ['dlc'],            source: 'local' },
    { title: 'Rise of the Tomb Raider',               short: 'Rise of TR',         group: 'Remedy',              img: steamImg(391220),   hasDlc: true,  tags: ['Экшн', 'Приключение', 'Открытый мир'],           opts: ['dlc'],            source: 'local' },

    // ── Mundfish ──────────────────────────────────────────────────
    { title: 'Atomic Heart - Premium Edition',        short: 'Atomic Heart',       group: 'Mundfish',            img: steamImg(668580),   hasDlc: true,  tags: ['Экшены', 'Приключенческие игры', 'Ролевые игры'], opts: ['dlc', 'ru'],      source: 'steam' },

    // ── marme1adker — аккаунт ─────────────────────────────────────
    { title: 'Альтушка для скуфа',         short: 'Альтушка для скуфа',        group: 'Инди • Разное',    img: steamImg(2901520),  tags: ['Инди', 'Необычное'],                                     opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'Ведьмак 3: Дикая Охота',     short: 'Ведьмак 3',                 group: 'CD Projekt Red',   img: steamImg(292030),   tags: ['Открытый мир', 'RPG', 'Сюжет', 'Фэнтези'],              opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'ЗВЁЗДНЫЕ ВОЙНЫ Джедаи: Павший Орден', short: 'SW Джедаи',        group: 'PlayStation',      img: steamImg(1172380),  tags: ['Экшн', 'Сюжет', 'Звёздные войны'],                      opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'Мистер Фурри',               short: 'Мистер Фурри',              group: 'Инди • Разное',    img: steamImg(2168720),  tags: ['Инди', 'Необычное'],                                     opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'Одни из нас™, Часть I',      short: 'Одни из нас Ч.I',           group: 'PlayStation',      img: steamImg(1888930),  tags: ['Хоррор', 'Сюжет', 'Выживание'],                         opts: ['ru'],             source: 'steam',  marme1adker: true },
    { title: 'Призрак Цусимы: Режиссёрская версия', short: 'Призрак Цусимы',   group: 'PlayStation',      img: steamImg(2215430),  tags: ['Открытый мир', 'Самурай', 'Стелс'],                     opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'Симулятор Чушпана',          short: 'Симулятор Чушпана',         group: 'Инди • Разное',    img: steamImg(2177200),  tags: ['Симулятор', 'Инди', 'Необычное'],                        opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'Хогвартс. Наследие',         short: 'Хогвартс',                  group: 'PlayStation',      img: steamImg(990080),   tags: ['Открытый мир', 'RPG', 'Фэнтези', 'Сюжет'],             opts: ['ru'],             source: 'local',  marme1adker: true },
    { title: 'Baldur\'s Gate 3',           short: 'BG3',                        group: 'Larian Studios',   img: steamImg(1086940),  tags: ['RPG', 'Кооп', 'Фэнтези', 'Сюжет'],                     opts: ['dlc', 'online'],  source: 'local',  marme1adker: true },
    { title: 'No Man\'s Sky',              short: 'No Man\'s Sky',              group: 'Hello Games',      img: steamImg(275850),   tags: ['Выживание', 'Космос', 'Исследование', 'Кооп'],          opts: ['dlc', 'online'],  source: 'local',  marme1adker: true },
    { title: 'ELDEN RING NIGHTREIGN',      short: 'ER Nightreign',              group: 'FromSoftware',     img: steamImg(2622380),  tags: ['Souls-like', 'Кооп', 'Хардкор'],                        opts: ['dlc', 'online'],  source: 'local',  marme1adker: true },
    { title: 'DARK SOULS™ II',             short: 'DS2',                        group: 'FromSoftware',     img: steamImg(236430),   tags: ['Souls-like', 'Хардкор', 'Экшн'],                        opts: ['dlc'],            source: 'local',  marme1adker: true },
    { title: 'DARK SOULS™ II: Scholar of the First Sin', short: 'DS2 SotFS',    group: 'FromSoftware',     img: steamImg(335300),   tags: ['Souls-like', 'Хардкор', 'Экшн'],                        opts: ['dlc'],            source: 'local',  marme1adker: true },
    { title: 'DARK SOULS™: REMASTERED',    short: 'DS1 R',                      group: 'FromSoftware',     img: steamImg(570940),   tags: ['Souls-like', 'Хардкор', 'Экшн'],                        opts: [],                 source: 'local',  marme1adker: true },
    { title: 'The Witcher 2: Assassins of Kings Enhanced Edition', short: 'Witcher 2', group: 'CD Projekt Red', img: steamImg(20920), tags: ['RPG', 'Сюжет', 'Фэнтези'],                          opts: [],                 source: 'local',  marme1adker: true },
    { title: 'Marvel\'s Spider-Man: Miles Morales', short: 'Miles Morales',     group: 'PlayStation',      img: steamImg(1817190),  tags: ['Открытый мир', 'Экшн', 'Супергерой'],                   opts: [],                 source: 'local',  marme1adker: true },
    { title: 'Marvel\'s Spider-Man Remastered', short: 'Spider-Man R',          group: 'PlayStation',      img: steamImg(1817070),  tags: ['Открытый мир', 'Экшн', 'Супергерой'],                   opts: [],                 source: 'local',  marme1adker: true },
    { title: 'Marvel Rivals',              short: 'Marvel Rivals',              group: 'PlayStation',      img: steamImg(2767030),  tags: ['Шутер', 'Супергерой', 'Мультиплеер'],                   opts: ['online'],         source: 'local',  marme1adker: true },
    { title: 'Lies of P',                  short: 'Lies of P',                  group: 'Инди • Разное',    img: steamImg(1627720),  tags: ['Souls-like', 'Хардкор', 'Сюжет'],                       opts: ['dlc'],            source: 'local',  marme1adker: true },
    { title: 'Rust',                       short: 'Rust',                       group: 'Инди • Разное',    img: steamImg(252490),   tags: ['Выживание', 'Крафт', 'Мультиплеер'],                    opts: ['online'],         source: 'local',  marme1adker: true },
    { title: 'Palworld',                   short: 'Palworld',                   group: 'Инди • Разное',    img: steamImg(1623730),  tags: ['Выживание', 'Крафт', 'Кооп', 'Для всех'],               opts: ['online'],         source: 'local',  marme1adker: true },
    { title: 'PEAK',                       short: 'PEAK',                       group: 'Инди • Разное',    img: steamImg(3527150),  tags: ['Выживание', 'Кооп', 'Экшн'],                            opts: ['online'],         source: 'local',  marme1adker: true },
    { title: 'Content Warning',            short: 'Content Warning',            group: 'Инди • Разное',    img: steamImg(2881650),  tags: ['Кооп', 'Хоррор', 'Необычное'],                          opts: ['online'],         source: 'local',  marme1adker: true },
    { title: 'Schedule I',                 short: 'Schedule I',                 group: 'Инди • Симулятор', img: steamImg(3164500),  tags: ['Симулятор', 'Открытый мир', 'Бизнес'],                   opts: ['online'],         source: 'local',  marme1adker: true },
    { title: 'ASTRONEER',                  short: 'ASTRONEER',                  group: 'Инди • Разное',    img: steamImg(361420),   tags: ['Выживание', 'Крафт', 'Исследование', 'Кооп'],          opts: ['online'],         source: 'local',  marme1adker: true },
    { title: 'Devil May Cry 4 Special Edition', short: 'DMC4 SE',              group: 'Инди • Разное',    img: steamImg(329050),   tags: ['Экшн', 'Слэшер', 'Хардкор'],                            opts: [],                 source: 'local',  marme1adker: true },
    { title: 'Devil May Cry HD Collection', short: 'DMC HD',                    group: 'Инди • Разное',    img: steamImg(631510),   tags: ['Экшн', 'Слэшер', 'Классика'],                           opts: [],                 source: 'local',  marme1adker: true },
];

// ── Загрузка игр — API-first ─────────────────────────────────────
//
//  Логика:
//   1. Пробуем загрузить весь каталог из API (Railway) — единый источник правды.
//   2. Если API недоступен (нет сети, Railway спит) — fallback на _localGames.
//   3. _localGames используется ТОЛЬКО как резервная копия и для первичного seed.
//
//  Seed (одноразово, делается из консоли или AdminPanel):
//    AdminSeed.run()   — заливает _localGames в БД, пропускает уже существующие.
//
async function fetchGames() {
  const apiBase =
    (typeof THEPASS_API_URL !== 'undefined' && THEPASS_API_URL)
      ? THEPASS_API_URL
      : (typeof AUTH_CONFIG !== 'undefined' && AUTH_CONFIG.BASE_URL)
        ? AUTH_CONFIG.BASE_URL
        : 'https://thepass-api.up.railway.app';

  try {
    const res = await fetch(`${apiBase}/api/games`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const apiGames = await res.json();

    if (apiGames && apiGames.length > 0) {
      // API — единственный источник правды.
      // Добавляем img из steamId если не пришёл с сервера.
      return apiGames.map(g => ({
        ...g,
        img: g.img || steamImg(g.steamId),
      }));
    }

    // API вернул пустой массив — БД ещё не заполнена.
    // Возвращаем локальные данные и подсказываем сделать seed.
    console.warn('[fetchGames] API вернул пустой список. Запусти AdminSeed.run() для первичного импорта.');
    return _localGames;

  } catch (e) {
    console.warn('[fetchGames] API недоступен, работаем локально:', e.message);
    return _localGames;
  }
}

// ── Утилита для первичного импорта локальных игр в БД ────────────
//
//  Использование (один раз, из консоли браузера под аккаунтом admin):
//    AdminSeed.run()
//
const AdminSeed = {
  async run() {
    const apiBase =
      (typeof THEPASS_API_URL !== 'undefined' && THEPASS_API_URL)
        ? THEPASS_API_URL
        : 'https://thepass-api.up.railway.app';

    const token =
      (typeof Auth !== 'undefined' && Auth.token)
        ? Auth.token
        : sessionStorage.getItem('thepass_token') || localStorage.getItem('thepass_token') || '';

    if (!token) {
      console.error('[AdminSeed] Нет токена. Войди под admin-аккаунтом.');
      return;
    }

    // Нормализуем поля под формат API
    const games = _localGames.map(g => {
      // Извлекаем steamId из img-ссылки если поля steamId нет
      let steamId = g.steamId || g.steam_id || 0;
      if (!steamId && g.img) {
        const m = g.img.match(/apps\/(\d+)\//);
        if (m) steamId = parseInt(m[1], 10);
      }
      return {
        title:        g.title        || '',
        short:        g.short        || '',
        group:        g.group        || 'Инди • Разное',
        steamId:      steamId,
        hasDlc:       !!g.hasDlc,
        source:       g.source       || 'local',
        marme1adker:  !!g.marme1adker,
        steampassUrl: g.steampassUrl || null,
        tags:         g.tags         || [],
        opts:         g.opts         || [],
      };
    });

    console.log(`[AdminSeed] Начинаю импорт ${games.length} игр...`);

    try {
      const res = await fetch(`${apiBase}/api/admin/games/seed`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ games }),
      });

      const data = await res.json();

      if (!res.ok) {
        console.error('[AdminSeed] Ошибка:', data.detail || res.status);
        return;
      }

      console.log(`[AdminSeed] ✅ Готово! Добавлено: ${data.added}, пропущено: ${data.skipped}`);
      if (typeof showToast === 'function') {
        showToast(`✅ Импорт завершён: +${data.added} игр`);
      }
    } catch (e) {
      console.error('[AdminSeed] Сетевая ошибка:', e.message);
    }
  }
};