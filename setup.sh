#!/bin/bash

ROUTER_IP="172.16.15.1"

echo "Install Apache PHP dan Rsyslog"

apt update -y

apt install apache2 php rsyslog -y

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
$logs = [];
$errorMessage = '';

// Membaca file Syslog
if (!is_readable($logFile)) {
    $errorMessage = 'File log tidak dapat dibaca. Periksa izin akses PHP.';
} else {
    $allLogs = file(
        $logFile,
        FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
    );

    foreach ($allLogs as $log) {
        if (
            strpos($log, 'WINBOX-NEW') !== false ||
            strpos($log, 'SSH-NEW') !== false
        ) {
            $logs[] = $log;
        }
    }

    // Log terbaru ditampilkan lebih dahulu
    $logs = array_reverse($logs);
}

// Mengamankan teks sebelum ditampilkan ke HTML
function e($value)
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        'UTF-8'
    );
}

// Mengolah satu baris Syslog
function parseLog($log)
{
    $data = [
        'waktu'       => '-',
        'ip_sumber'   => '-',
        'mac_sumber'  => '-',
        'ip_tujuan'   => '-',
        'port_tujuan' => '-',
        'kegiatan'    => 'Aktivitas jaringan'
    ];

    // Mengambil timestamp Syslog
// Mengambil timestamp Syslog dan mengonversinya ke WIB
if (preg_match(
    '/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))/',
    $log,
    $m
)) {
    try {
        $waktu = new DateTimeImmutable($m[1]);

        $waktu = $waktu->setTimezone(
            new DateTimeZone('Asia/Jakarta')
        );

        $data['waktu'] = $waktu->format('d-m-Y H:i:s');

    } catch (Exception $e) {
        $data['waktu'] = 'Format waktu tidak valid';
    }
}

    // Mengambil MAC address sumber jika tersedia
    if (preg_match(
        '/src-mac\s+([0-9a-fA-F:]{17})/',
        $log,
        $m
    )) {
        $data['mac_sumber'] = strtoupper($m[1]);
    }

    // Mengambil IP sumber, port sumber, IP tujuan, port tujuan
    if (preg_match(
        '/(\d{1,3}(?:\.\d{1,3}){3}):(\d+)->(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/',
        $log,
        $m
    )) {
        $data['ip_sumber'] = $m[1];
        $data['ip_tujuan'] = $m[3];
        $data['port_tujuan'] = $m[4];
    }

    // Menentukan jenis aktivitas berdasarkan prefix
    if (strpos($log, 'WINBOX-NEW') !== false) {
        $data['kegiatan'] = 'Koneksi baru Winbox';
    } elseif (strpos($log, 'SSH-NEW') !== false) {
        $data['kegiatan'] = 'Koneksi baru SSH';
    }

    return $data;
}

?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <meta http-equiv="refresh" content="10">

    <title>Monitoring Akses MikroTik</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            margin: 25px;
            background: #f4f6f9;
            color: #222;
        }

        h2 {
            margin-bottom: 5px;
        }

        .subtitle {
            color: #666;
            margin-bottom: 20px;
        }

        .summary {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 20px;
        }

        .card {
            background: #fff;
            padding: 18px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,.06);
            flex: 1;
            min-width: 180px;
        }

        .card .label {
            font-size: 13px;
            color: #666;
        }

        .card .number {
            display: block;
            font-size: 27px;
            font-weight: bold;
            margin-top: 8px;
        }

        .table-container {
            overflow-x: auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,.06);
        }

        table {
            width: 100%;
            min-width: 900px;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
            text-align: left;
            font-size: 13px;
        }

        th {
            background: #17365d;
            color: white;
        }

        tr:hover {
            background: #eef5ff;
        }

        .badge {
            display: inline-block;
            padding: 5px 8px;
            border-radius: 5px;
            white-space: nowrap;
        }

        .winbox {
            background: #dbeafe;
            color: #1d4ed8;
        }

        .ssh {
            background: #dcfce7;
            color: #166534;
        }

        .empty {
            text-align: center;
            padding: 25px;
            color: #666;
        }

        .error {
            background: #fee2e2;
            color: #991b1b;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
        }

        .footer {
            color: #777;
            font-size: 12px;
            margin-top: 15px;
        }
    </style>
</head>

<body>

    <h2>Monitoring Akses MikroTik</h2>

    <div class="subtitle">
        Monitoring koneksi Winbox dan SSH melalui Syslog Debian Server
    </div>

    <?php if ($errorMessage !== ''): ?>

        <div class="error">
            <?= e($errorMessage) ?>
        </div>

    <?php else: ?>

        <?php
        $totalWinbox = 0;
        $totalSSH = 0;

        foreach ($logs as $log) {
            if (strpos($log, 'WINBOX-NEW') !== false) {
                $totalWinbox++;
            } elseif (strpos($log, 'SSH-NEW') !== false) {
                $totalSSH++;
            }
        }
        ?>

        <div class="summary">
            <div class="card">
                <span class="label">Total log Winbox</span>
                <span class="number"><?= $totalWinbox ?></span>
            </div>

            <div class="card">
                <span class="label">Total log SSH</span>
                <span class="number"><?= $totalSSH ?></span>
            </div>

            <div class="card">
                <span class="label">Total aktivitas tercatat</span>
                <span class="number"><?= count($logs) ?></span>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>No</th>
                        <th>Waktu</th>
                        <th>IP Sumber</th>
                        <th>MAC Sumber</th>
                        <th>IP Tujuan</th>
                        <th>Port Tujuan</th>
                        <th>Nama Kegiatan</th>
                    </tr>
                </thead>

                <tbody>

                <?php if (empty($logs)): ?>

                    <tr>
                        <td colspan="7" class="empty">
                            Belum ada log koneksi Winbox atau SSH.
                        </td>
                    </tr>

                <?php else: ?>

                    <?php foreach ($logs as $i => $log): ?>
                        <?php $item = parseLog($log); ?>

                        <tr>
                            <td><?= $i + 1 ?></td>
                            <td><?= e($item['waktu']) ?></td>
                            <td><?= e($item['ip_sumber']) ?></td>
                            <td><?= e($item['mac_sumber']) ?></td>
                            <td><?= e($item['ip_tujuan']) ?></td>
                            <td><?= e($item['port_tujuan']) ?></td>

                            <td>
                                <?php if (
                                    strpos($log, 'WINBOX-NEW') !== false
                                ): ?>
                                    <span class="badge winbox">
                                        <?= e($item['kegiatan']) ?>
                                    </span>
                                <?php else: ?>
                                    <span class="badge ssh">
                                        <?= e($item['kegiatan']) ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                        </tr>

                    <?php endforeach; ?>

                <?php endif; ?>

                </tbody>
            </table>
        </div>

        <div class="footer">
            Halaman diperbarui otomatis setiap 10 detik.
            Data bersumber dari file Syslog MikroTik.
        </div>

    <?php endif; ?>

</body>
</html>
EOF

systemctl restart apache2
systemctl restart rsyslog

echo "Monitoring Siap Digunakan"