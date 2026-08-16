-- VulnApp seed data
USE vulnapp;

INSERT INTO users (id, username, password, fullname, email, role, bio) VALUES
  (1, 'admin',  '21232f297a57a5a743894a0e4a801fc3', 'Administrator', 'admin@vulnapp.local',  'admin', 'Owner of this shop. Has access to everything.'),
  (2, 'alice',  '7abdccbea8473767e91378e37850d296', 'Alice Pratama',  'alice@vulnapp.local',  'user',  'Front-end developer & part-time gamer.'),
  (3, 'bob',    '2acba7f51acfd4fd5102ad090fc612ee', 'Bobby Santoso',  'bob@vulnapp.local',    'user',  'Back-end engineer who never uses prepared statements.'),
  (4, 'carol',  '35d9b8a73dad4919a46dfed32701f481', 'Carol Wijaya',   'carol@vulnapp.local',  'user',  'QA engineer. Breaking things is my job.'),
  (5, 'dave',   '70b9f55c5b2ab6ab9e5a3fed086f1ce7', 'David Haryanto', 'dave@vulnapp.local',   'user',  'DevOps. Automates everything, secures nothing.'),
  (6, 'eve',    '7a8a900ed78ded2820a0e706b4a6de57', 'Evelyn Gunawan', 'eve@vulnapp.local',    'user',  'Security researcher. Always listening.');

INSERT INTO products (id, name, description, price, category, stock) VALUES
  (1,  'Mechanical Keyboard TKL', 'Hot-swappable RGB mechanical keyboard, brown switches.', 899000,  'electronics', 25),
  (2,  'Wireless Mouse Pro',      '2.4GHz + Bluetooth, 16000 DPI, 70h battery.',             349000,  'electronics', 40),
  (3,  '27" IPS Monitor',         'QHD 144Hz, 1ms, HDR10, height-adjustable stand.',         2899000, 'electronics', 12),
  (4,  'USB-C Docking Station',   '10-in-1 hub with 100W PD passthrough.',                   1199000, 'electronics', 30),
  (5,  'Espresso Machine',        '15-bar pump, built-in grinder, milk frother.',            4599000, 'home',      8),
  (6,  'Aeropress Coffee Maker',  'Portable manual coffee press, includes 350 filters.',      550000,  'home',      60),
  (7,  'Standing Desk 120cm',     'Electric height-adjustable desk, 3 memory presets.',       3299000, 'home',      10),
  (8,  'Ergonomic Office Chair',  'Mesh back, lumbar support, 4D armrests.',                  2199000, 'home',      15),
  (9,  'Noise-Cancelling Headset','ANC, 40h battery, multipoint Bluetooth.',                  1999000, 'audio',     22),
  (10, 'Portable Bluetooth Speaker','IPX7 waterproof, 24h playtime, stereo pairing.',         749000,  'audio',     35),
  (11, 'USB Microphone',          'Condenser mic with pop filter and shock mount.',           899000,  'audio',     18),
  (12, 'Webcam 4K',               '4K30, auto-framing, dual noise-cancelling mics.',          1199000, 'audio',     14);

INSERT INTO posts (id, user_id, title, body, created_at) VALUES
  (1, 2, 'Welcome to our new store!', 'We just launched VulnApp Shop. Browse our catalog and let us know what you think in the comments below.', '2026-07-01 09:00:00'),
  (2, 3, 'How I deploy the store', 'Simple: ssh to the server, git pull, restart. No tests, no pipeline. What could possibly go wrong?', '2026-07-05 14:30:00'),
  (3, 4, 'QA corner: report bugs here', 'Found a bug? Describe it below. Please include the exact URL so we can reproduce it.', '2026-07-10 10:15:00'),
  (4, 5, 'Server maintenance schedule', 'We take the site down every Sunday 03:00–04:00 WIB. Backups happen automatically (we think).', '2026-07-20 21:45:00'),
  (5, 1, 'Admin announcement', 'New stock arriving for the electronics category. Stay tuned!', '2026-08-01 08:20:00');

INSERT INTO comments (id, post_id, user_id, body, created_at) VALUES
  (1, 1, 3, 'Nice shop! Love the keyboard.', '2026-07-01 10:00:00'),
  (2, 1, 4, 'The 27" monitor is back in stock?', '2026-07-02 11:20:00'),
  (3, 1, 5, 'Server was down for 5 minutes during the launch, sorry!', '2026-07-02 13:40:00'),
  (4, 2, 2, 'You should really use prepared statements, Bob.', '2026-07-06 09:10:00'),
  (5, 2, 3, 'It works though. Ship it.', '2026-07-06 09:45:00'),
  (6, 3, 6, 'I found an error page when searching for quotes. Details: /search?q=%27', '2026-07-11 15:00:00'),
  (7, 3, 1, 'Thanks Eve, we will look into it.', '2026-07-11 16:30:00'),
  (8, 4, 6, 'Do you have a public changelog?', '2026-07-21 08:00:00'),
  (9, 4, 5, 'Not yet, but soon.', '2026-07-21 08:05:00'),
  (10, 5, 3, 'Any discounts for the desk?', '2026-08-02 09:00:00'),
  (11, 5, 1, 'There is a bundle deal, check the product page.', '2026-08-02 09:30:00'),
  (12, 5, 4, 'I can confirm the bundle works great.', '2026-08-03 12:00:00');