#!/bin/bash

ROUTER_IP="172.16.15.1"

echo "Install Apache PHP dan Rsyslog"

apt update -y

apt install apache2 php php-mbstring rsyslog logrotate -y

echo "Aktifkan Syslog UDP"

sed -i 's/#module(load="imudp")/module(load="imudp")/' /etc/rsyslog.conf

sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf

echo "Buat file log"

touch /var/log/mikrotik.log

chmod 644 /var/log/mikrotik.log

echo "Konfigurasi Router Log"

cat > /etc/rsyslog.d/mikrotik.conf << EOF
if \$fromhost-ip == '$ROUTER_IP' then /var/log/mikrotik.log
& stop
EOF

systemctl restart rsyslog

echo "Install Dashboard"

cat > /var/www/html/index.php << 'EOF'
<?php
date_default_timezone_set('Asia/Jakarta');

$logFile = '/var/log/mikrotik.log';
$maxLines = 10000;
$maxDisplay = 500;

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function parseEvent($line) {
    $line = trim($line);

    // Format syslog:
    // timestamp router-ip topics pesan
    if (!preg_match(
        '/^(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/',
        $line,
        $parts
    )) {
        return null;
    }

    $timestamp = $parts[1];
    $topics = $parts[3];
    $message = $parts[4];

    // Abaikan aktivitas web-proxy
    if (stripos($topics, 'web-proxy') !== false) {
        return null;
    }

    $event = null;
    $username = '-';
    $ip = '-';
    $service = '-';
    $status = '';
    $detail = $message;

    // 1. Koneksi baru Winbox
    if (preg_match('/WINBOX-NEW/i', $message)) {
        $event = 'Koneksi';
        $service = 'Winbox';
        $status = 'Koneksi baru';
    }
    // 2. Koneksi baru SSH
    elseif (preg_match('/SSH-NEW/i', $message)) {
        $event = 'Koneksi';
        $service = 'SSH';
        $status = 'Koneksi baru';
    }

    // Ambil IP sumber dari log firewall.
    // Contoh: 172.16.3.20:54321->172.16.15.1:8291
    if ($event === 'Koneksi') {
        if (preg_match(
            '/(\d{1,3}(?:\.\d{1,3}){3}):\d+\s*->/',
            $message,
            $m
        )) {
            $ip = $m[1];
        } elseif (preg_match(
            '/src-address=(\d{1,3}(?:\.\d{1,3}){3})/',
            $message,
            $m
        )) {
            $ip = $m[1];
        }
    }

    // 3. Login gagal
    if (preg_match(
        '/login failure for user\s+(\S+)\s+from\s+(\S+)\s+via\s+(\S+)/i',
        $message,
        $m
    )) {
        $event = 'Autentikasi';
        $status = 'Login gagal';
        $username = $m[1];
        $ip = $m[2];
        $service = $m[3];
    }
    // 4. Login berhasil
    elseif (preg_match(
        '/user\s+(\S+)\s+logged in from\s+(\S+)\s+via\s+(\S+)/i',
        $message,
        $m
    )) {
        $event = 'Autentikasi';
        $status = 'Login berhasil';
        $username = $m[1];
        $ip = $m[2];
        $service = $m[3];
    }
    // 5. Logout
    elseif (preg_match(
        '/user\s+(\S+)\s+logged out(?: from\s+(\S+))?(?:\s+via\s+(\S+))?/i',
        $message,
        $m
    )) {
        $event = 'Autentikasi';
        $status = 'Logout';
        $username = $m[1];
        $ip = !empty($m[2]) ? $m[2] : '-';
        $service = !empty($m[3]) ? $m[3] : '-';
    }

    // Abaikan semua log selain koneksi dan autentikasi.
    if ($event === null) {
        return null;
    }

    // Ubah timestamp ISO-8601 menjadi WIB.
    try {
        $date = new DateTimeImmutable($timestamp);
        $date = $date->setTimezone(
            new DateTimeZone('Asia/Jakarta')
        );
        $time = $date->format('d-m-Y H:i:s');
    } catch (Exception $e) {
        $time = $timestamp;
    }

    return [
        'timestamp' => $timestamp,
        'waktu' => $time,
        'event' => $event,
        'status' => $status,
        'username' => $username,
        'ip' => $ip,
        'service' => $service,
        'detail' => $detail
    ];
}

$filter = $_GET['jenis'] ?? 'semua';

$allowedFilters = [
    'semua',
    'koneksi',
    'berhasil',
    'gagal',
    'logout'
];

if (!in_array($filter, $allowedFilters, true)) {
    $filter = 'semua';
}

$events = [];
$error = '';

if (!is_readable($logFile)) {
    $error = 'File log tidak dapat dibaca. Periksa izin akses PHP.';
} else {
    $file = new SplFileObject($logFile, 'r');
    $file->seek(PHP_INT_MAX);
    $totalLines = $file->key() + 1;

    $startLine = max(0, $totalLines - $maxLines);
    $file->seek($startLine);

    $lines = [];

    while (!$file->eof()) {
        $line = trim($file->fgets());

        if ($line !== '') {
            $lines[] = $line;
        }
    }

    // Log terbaru ditampilkan paling atas.
    foreach (array_reverse($lines) as $line) {
        $item = parseEvent($line);

        if ($item === null) {
            continue;
        }

        $events[] = $item;
    }
}

$totalKoneksi = 0;
$totalBerhasil = 0;
$totalGagal = 0;
$totalLogout = 0;

foreach ($events as $item) {
    if ($item['event'] === 'Koneksi') {
        $totalKoneksi++;
    }

    if ($item['status'] === 'Login berhasil') {
        $totalBerhasil++;
    }

    if ($item['status'] === 'Login gagal') {
        $totalGagal++;
    }

    if ($item['status'] === 'Logout') {
        $totalLogout++;
    }
}

// Filter hanya memengaruhi tabel, bukan angka ringkasan.
$filteredEvents = array_values(array_filter(
    $events,
    function ($item) use ($filter) {
        return match ($filter) {
            'koneksi' => $item['event'] === 'Koneksi',
            'berhasil' => $item['status'] === 'Login berhasil',
            'gagal' => $item['status'] === 'Login gagal',
            'logout' => $item['status'] === 'Logout',
            default => true
        };
    }
));

$filteredEvents = array_slice($filteredEvents, 0, $maxDisplay);

function badgeClass($status) {
    return match ($status) {
        'Login berhasil' => 'success',
        'Login gagal' => 'danger',
        'Logout' => 'muted',
        'Koneksi baru' => 'info',
        default => 'muted'
    };
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="10">
<title>Monitoring MikroTik</title>

<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    padding: 24px;
    background: #f1f5f9;
    color: #1e293b;
    font-family: Arial, Helvetica, sans-serif;
}

.container {
    max-width: 1400px;
    margin: auto;
}

.header {
    background: #172554;
    color: white;
    padding: 25px;
    border-radius: 12px;
    margin-bottom: 20px;
}

.header h1 {
    margin: 0 0 8px;
    font-size: 26px;
}

.header p {
    margin: 0;
    color: #dbeafe;
}

.cards {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}

.card, .panel {
    background: white;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(15, 23, 42, .05);
}

.card {
    padding: 20px;
}

.card .label {
    color: #64748b;
    font-size: 13px;
}

.card .number {
    margin-top: 10px;
    font-size: 29px;
    font-weight: bold;
}

.panel {
    padding: 20px;
}

.panel h2 {
    margin: 0 0 8px;
    font-size: 20px;
}

.info {
    color: #64748b;
    font-size: 13px;
    margin-bottom: 18px;
    line-height: 1.6;
}

.toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 18px;
}

select, button {
    padding: 10px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 7px;
    background: white;
    color: #1e293b;
    font-size: 14px;
}

button {
    background: #1d4ed8;
    border-color: #1d4ed8;
    color: white;
    cursor: pointer;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    white-space: nowrap;
}

th, td {
    padding: 13px 12px;
    border-bottom: 1px solid #e2e8f0;
    text-align: left;
}

th {
    background: #f8fafc;
    color: #475569;
}

.badge {
    display: inline-block;
    padding: 5px 9px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
}

.success { background: #dcfce7; color: #166534; }
.danger { background: #fee2e2; color: #991b1b; }
.info { background: #dbeafe; color: #1d4ed8; }
.muted { background: #e2e8f0; color: #334155; }

.alert {
    padding: 14px;
    border-radius: 8px;
    margin-bottom: 18px;
    background: #fff7ed;
    color: #9a3412;
}

.empty {
    padding: 28px;
    text-align: center;
    color: #64748b;
}

.footer {
    margin-top: 18px;
    text-align: center;
    color: #64748b;
    font-size: 12px;
}

@media (max-width: 750px) {
    body { padding: 12px; }
    .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .card { padding: 15px; }
    .card .number { font-size: 24px; }
    .panel { padding: 12px; }
    .header h1 { font-size: 22px; }
}
</style>
</head>

<body>
<div class="container">

    <header class="header">
        <h1>Monitoring MikroTik</h1>
        <p>Pemantauan koneksi Winbox, SSH, dan autentikasi router</p>
    </header>

    <?php if ($error !== ''): ?>
        <div class="alert"><?= h($error) ?></div>
    <?php endif; ?>

    <section class="cards">
        <div class="card">
            <div class="label">Koneksi Baru</div>
            <div class="number"><?= $totalKoneksi ?></div>
        </div>

        <div class="card">
            <div class="label">Login Berhasil</div>
            <div class="number"><?= $totalBerhasil ?></div>
        </div>

        <div class="card">
            <div class="label">Login Gagal</div>
            <div class="number"><?= $totalGagal ?></div>
        </div>

        <div class="card">
            <div class="label">Logout</div>
            <div class="number"><?= $totalLogout ?></div>
        </div>
    </section>

    <section class="panel">
        <h2>Riwayat Aktivitas</h2>

        <div class="info">
            Pembaruan otomatis setiap 10 detik. Waktu ditampilkan dalam WIB.
            Ringkasan dihitung dari log yang masih tersedia dalam file,
            maksimal <?= number_format($maxLines) ?> baris terbaru.
        </div>

        <form method="get" class="toolbar">
            <div>
                <label for="jenis">Filter aktivitas: </label>
                <select name="jenis" id="jenis" onchange="this.form.submit()">
                    <option value="semua" <?= $filter === 'semua' ? 'selected' : '' ?>>
                        Semua aktivitas
                    </option>
                    <option value="koneksi" <?= $filter === 'koneksi' ? 'selected' : '' ?>>
                        Koneksi Winbox / SSH
                    </option>
                    <option value="berhasil" <?= $filter === 'berhasil' ? 'selected' : '' ?>>
                        Login berhasil
                    </option>
                    <option value="gagal" <?= $filter === 'gagal' ? 'selected' : '' ?>>
                        Login gagal
                    </option>
                    <option value="logout" <?= $filter === 'logout' ? 'selected' : '' ?>>
                        Logout
                    </option>
                </select>
            </div>

            <button type="submit">Muat ulang</button>
        </form>

        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>No.</th>
                    <th>Waktu (WIB)</th>
                    <th>Jenis</th>
                    <th>Aktivitas</th>
                    <th>Username</th>
                    <th>IP Sumber</th>
                    <th>Layanan</th>
                    <th>Detail Log</th>
                </tr>
                </thead>

                <tbody>
                <?php if (empty($filteredEvents)): ?>
                    <tr>
                        <td colspan="8" class="empty">
                            Belum ada log yang cocok dengan filter ini.
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($filteredEvents as $i => $item): ?>
                        <tr>
                            <td><?= $i + 1 ?></td>
                            <td><?= h($item['waktu']) ?></td>
                            <td><?= h($item['event']) ?></td>
                            <td>
                                <span class="badge <?= badgeClass($item['status']) ?>">
                                    <?= h($item['status']) ?>
                                </span>
                            </td>
                            <td><?= h($item['username']) ?></td>
                            <td><?= h($item['ip']) ?></td>
                            <td><?= h($item['service']) ?></td>
                            <td title="<?= h($item['detail']) ?>">
                                <?= h(mb_strimwidth($item['detail'], 0, 90, '...')) ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>

    <footer class="footer">
        Monitoring MikroTik &bull; Syslog Debian 12 &bull; Refresh 10 detik
    </footer>

</div>
</body>
</html>
EOF

systemctl restart apache2
systemctl restart rsyslog

echo "Monitoring Siap Digunakan"
