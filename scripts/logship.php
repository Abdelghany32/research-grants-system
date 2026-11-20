<?php
declare(strict_types=1);
// Log shipper: copies new lines of the PostgreSQL JSON log and the application error log into an append-only archive
// where every record carries the SHA-256 of the previous one (a hash chain). Changing, removing or reordering any
// shipped record breaks every hash after it, and `verify` finds the first break.
//
//   php logship.php run                    ship forever (the container's job)
//   php logship.php verify [seq:hash]     recompute the chain; exit 1 at the first broken record. With an anchor taken earlier
//                                          (`head`), also proves nothing up to that record was cut off
//   php logship.php export <since> [src]   print records since an ISO time, as  "<time> [<pid>] <user>@<db> <message>"
//   php logship.php head                   print the newest anchor  seq:hash  (keep it somewhere the shipper cannot write)
//
// Archive:  /out/archive.ndjson  (one JSON object per line)    State: /out/state.json (read offsets)
const SOURCES = ['db' => '/in/db', 'app' => '/in/app'];
$OUT = getenv('LOGSHIP_OUT') ?: '/out';
$ARCHIVE = "$OUT/archive.ndjson";
$STATE = "$OUT/state.json";

function head(string $archive): array
{
    if (!is_file($archive) || filesize($archive) === 0) {
        return [0, str_repeat('0', 64)];
    }
    $fh = fopen($archive, 'rb');
    fseek($fh, max(0, filesize($archive) - 4_194_304));   // a record is at most a few KB: the last complete line is inside this tail
    $tail = (string) stream_get_contents($fh);
    fclose($fh);
    $lines = array_values(array_filter(explode("\n", $tail)));
    $last = json_decode((string) end($lines), true);
    return is_array($last) ? [(int) $last['seq'], (string) $last['hash']] : [0, str_repeat('0', 64)];
}

function link_hash(string $prev, int $seq, string $src, string $file, string $line): string
{
    return hash('sha256', $prev . '|' . $seq . '|' . $src . '|' . $file . '|' . $line);
}

function ship(string $archive, string $stateFile): int
{
    $state = is_file($stateFile) ? (json_decode((string) file_get_contents($stateFile), true) ?: []) : [];
    [$seq, $prev] = head($archive);
    $out = fopen($archive, 'ab');
    $count = 0;
    foreach (SOURCES as $src => $dir) {
        $files = array_merge(glob("$dir/*.log") ?: [], glob("$dir/*.json") ?: []);   // PostgreSQL writes *.log.json
        sort($files);
        foreach ($files as $path) {
            $key = $src . ':' . basename($path);
            $size = (int) filesize($path);
            $off = (int) ($state[$key] ?? 0);
            if ($size < $off) {
                $off = 0;                                  // truncated or rotated in place: ship it again from the start
            }
            if ($size === $off) {
                continue;
            }
            $in = fopen($path, 'rb');
            fseek($in, $off);
            while (($line = fgets($in)) !== false) {
                if (!str_ends_with($line, "\n")) {
                    break;                                 // a half-written line: wait for the rest
                }
                $off += strlen($line);
                $line = rtrim($line, "\n");
                if ($line === '') {
                    continue;
                }
                $seq++;
                $hash = link_hash($prev, $seq, $src, basename($path), $line);
                fwrite($out, json_encode(['seq' => $seq, 'at' => gmdate('c'), 'src' => $src, 'file' => basename($path), 'line' => $line, 'prev' => $prev, 'hash' => $hash],
                    JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
                $prev = $hash;
                $count++;
            }
            fclose($in);
            $state[$key] = $off;
        }
    }
    fflush($out);
    fclose($out);
    if ($count > 0) {
        file_put_contents($stateFile, json_encode($state), LOCK_EX);
    }
    return $count;
}

function verify(string $archive, ?string $anchor = null): int
{
    if (!is_file($archive)) {
        echo "no archive yet\n";
        return 0;
    }
    $prev = str_repeat('0', 64);
    $n = 0;
    $anchored = false;
    $fh = fopen($archive, 'rb');
    while (($raw = fgets($fh)) !== false) {
        $r = json_decode($raw, true);
        $n++;
        if (!is_array($r) || $r['prev'] !== $prev || $r['seq'] !== $n || !hash_equals(link_hash($prev, $r['seq'], $r['src'], $r['file'], $r['line']), $r['hash'])) {
            echo "BROKEN at record $n: the archive was changed, reordered or truncated here\n";
            return 1;
        }
        $prev = $r['hash'];
        if ($anchor !== null && $anchor === $n . ':' . $prev) {
            $anchored = true;
        }
    }
    if ($anchor !== null && empty($anchored)) {
        echo "BROKEN: the anchored record $anchor is not in the archive (it was truncated or rewritten)\n";
        return 1;
    }
    echo "OK: $n records, chain intact" . ($anchor !== null ? ", anchor $anchor present" : '') . ", head $prev\n";
    return 0;
}

function pretty(array $r): ?string
{
    if ($r['src'] === 'app') {
        return substr($r['at'], 0, 19) . ' app ' . $r['line'];
    }
    $j = json_decode($r['line'], true);
    if (!is_array($j)) {
        return $r['line'];                                  // a plain startup line
    }
    $ts = preg_replace('/ UTC$/', '', (string) ($j['timestamp'] ?? ''));
    return sprintf('%s [%s] %s@%s %s: %s%s', $ts, $j['pid'] ?? '?', $j['user'] ?? '', $j['dbname'] ?? '', $j['error_severity'] ?? '',
        $j['message'] ?? '', isset($j['statement']) ? ' | STATEMENT: ' . $j['statement'] : '') .
        (isset($j['application_name']) && $j['application_name'] !== '' ? ' application_name=' . $j['application_name'] : '');
}

$cmd = $argv[1] ?? 'run';
switch ($cmd) {
    case 'run':
        while (true) {
            ship($ARCHIVE, $STATE);
            sleep(2);
        }
        // no break (never returns)
    case 'verify':
        exit(verify($ARCHIVE, $argv[2] ?? null));
    case 'head':
        [$hs, $hh] = head($ARCHIVE);
        echo $hs . ':' . $hh, "\n";
        exit(0);
    case 'export':
        $since = strtotime((string) ($argv[2] ?? '1970-01-01')) ?: 0;
        $only = $argv[3] ?? null;
        $fh = is_file($ARCHIVE) ? fopen($ARCHIVE, 'rb') : null;
        while ($fh && ($raw = fgets($fh)) !== false) {
            $r = json_decode($raw, true);
            if (!is_array($r) || ($only !== null && $r['src'] !== $only)) {
                continue;
            }
            $j = $r['src'] === 'db' ? json_decode($r['line'], true) : null;
            $t = strtotime($j['timestamp'] ?? $r['at']);
            if ($t !== false && $t >= $since && ($line = pretty($r)) !== null) {
                echo $line, "\n";
            }
        }
        exit(0);
    default:
        fwrite(STDERR, "usage: logship.php run|verify|head|export <since> [db|app]\n");
        exit(2);
}
