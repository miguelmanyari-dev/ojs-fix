<?php
/**
 * MIT License, Copyright (c) 2026 Miguel Manyari.
 * Local, fail-closed antivirus and attachment policy. Never trusts browser MIME.
 */
namespace OjsFix;

final class AttachmentRejected extends \RuntimeException
{
    public string $reason;
    public int $status;
    public function __construct(string $reason, int $status = 422)
    {
        parent::__construct($reason);
        $this->reason = $reason;
        $this->status = $status;
    }
}

final class AttachmentGate
{
    private array $policy;
    public function __construct(string $policyPath)
    {
        if (!is_file($policyPath) || is_link($policyPath)) {
            throw new AttachmentRejected('configuration_unavailable', 503);
        }
        $policy = require $policyPath;
        if (!is_array($policy) || !isset($policy['socket'], $policy['private_dir'], $policy['temp_dir'],
                $policy['max_bytes'], $policy['allowed_extensions']) ||
                (!str_starts_with($policy['socket'], 'unix:///') &&
                 !preg_match('~^tls://127[.]0[.]0[.]1:[0-9]{4,5}$~D', $policy['socket'])) ||
                $policy['max_bytes'] < 1 || $policy['max_bytes'] > 100 * 1024 * 1024) {
            throw new AttachmentRejected('configuration_unavailable', 503);
        }
        $this->policy = $policy;
    }

    public function checkUploads(array $uploads): void
    {
        $count = 0;
        foreach ($uploads as $upload) {
            foreach ($this->flatten($upload) as $file) {
                if ($file['error'] === UPLOAD_ERR_NO_FILE) {
                    continue;
                }
                if (++$count > 20 || $file['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'])) {
                    throw new AttachmentRejected('invalid_upload');
                }
                $this->checkPath($file['tmp_name'], $file['name'], true);
            }
        }
    }

    private function flatten(array $file): array
    {
        if (!isset($file['name'], $file['tmp_name'], $file['error'])) {
            throw new AttachmentRejected('invalid_upload');
        }
        if (!is_array($file['name'])) {
            if (!is_string($file['name']) || !is_string($file['tmp_name']) || !is_int($file['error'])) {
                throw new AttachmentRejected('invalid_upload');
            }
            return [$file];
        }
        $out = [];
        foreach ($file['name'] as $key => $name) {
            $out = array_merge($out, $this->flatten([
                'name' => $name, 'tmp_name' => $file['tmp_name'][$key] ?? null,
                'error' => $file['error'][$key] ?? null,
            ]));
            if (count($out) > 20) {
                throw new AttachmentRejected('too_many_uploads');
            }
        }
        return $out;
    }

    private function filename(string $name): string
    {
        if ($name === '' || strlen($name) > 250 || preg_match('/[\x00-\x1f\x7f\\\\\/:]/', $name) ||
                preg_match('/[. ]$/', $name) || preg_match('/[\x{202a}-\x{202e}\x{2066}-\x{2069}]/u', $name)) {
            throw new AttachmentRejected('unsafe_filename');
        }
        if (preg_match('/(?:^|\.)(?:exe|dll|msi|com|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|url|php[0-9]*|phtml|phar|sh|py|pl|jar|zip|rar|7z|docm|dotm|xlsm|pptm)(?:\.|$)/i', $name)) {
            throw new AttachmentRejected('executable_or_macro_extension');
        }
        $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        if (!in_array($extension, $this->policy['allowed_extensions'], true)) {
            throw new AttachmentRejected('file_type_not_allowed');
        }
        return $extension;
    }

    private function snapshot(string $path, bool $upload): array
    {
        $root = realpath($upload ? $this->policy['temp_dir'] : $this->policy['private_dir']);
        $real = realpath($path);
        if ($root === false || $real === false || !str_starts_with($real, $root . DIRECTORY_SEPARATOR) ||
                !is_file($real) || is_link($path)) {
            throw new AttachmentRejected('invalid_file_location');
        }
        for ($part = $path; $part !== $root && dirname($part) !== $part; $part = dirname($part)) {
            if (is_link($part)) {
                throw new AttachmentRejected('symlink_not_allowed');
            }
        }
        $source = @fopen($path, 'rb');
        if ($source === false) {
            throw new AttachmentRejected('file_unavailable', 503);
        }
        $temporary = null;
        try {
            $stat = fstat($source);
            $entry = @lstat($path);
            if (!$stat || !$entry || ($stat['mode'] & 0170000) !== 0100000 ||
                    $stat['ino'] !== $entry['ino'] || $stat['dev'] !== $entry['dev']) {
                throw new AttachmentRejected('file_changed');
            }
            if ($stat['size'] < 1 || $stat['size'] > $this->policy['max_bytes']) {
                throw new AttachmentRejected('file_size_not_allowed', 413);
            }
            $temporary = @tempnam($this->policy['temp_dir'], 'ojs-fix-snapshot-');
            if ($temporary === false || dirname($temporary) !== realpath($this->policy['temp_dir'])) {
                throw new AttachmentRejected('temporary_storage_unavailable', 503);
            }
            chmod($temporary, 0600);
            $output = fopen($temporary, 'wb');
            if ($output === false) {
                throw new AttachmentRejected('temporary_storage_unavailable', 503);
            }
            $bytes = 0;
            $hash = hash_init('sha256');
            try {
                while (!feof($source)) {
                    $block = fread($source, 65536);
                    if ($block === false) {
                        throw new AttachmentRejected('file_unavailable', 503);
                    }
                    $bytes += strlen($block);
                    if ($bytes > $this->policy['max_bytes']) {
                        throw new AttachmentRejected('file_size_not_allowed', 413);
                    }
                    hash_update($hash, $block);
                    if (fwrite($output, $block) !== strlen($block)) {
                        throw new AttachmentRejected('temporary_storage_unavailable', 503);
                    }
                }
            } finally {
                fclose($output);
            }
            $after = fstat($source);
            if ($bytes !== $stat['size'] || $after['mtime'] !== $stat['mtime'] || $after['ctime'] !== $stat['ctime']) {
                throw new AttachmentRejected('file_changed');
            }
            return ['path' => $temporary, 'bytes' => $bytes, 'sha256' => hash_final($hash)];
        } catch (\Throwable $error) {
            if (is_string($temporary) && is_file($temporary)) {
                unlink($temporary);
            }
            throw $error;
        } finally {
            fclose($source);
        }
    }

    private static function writeAll($socket, string $data, float $deadline): void
    {
        $offset = 0;
        while ($offset < strlen($data)) {
            if (microtime(true) >= $deadline) {
                throw new AttachmentRejected('antivirus_timeout', 503);
            }
            $sent = @fwrite($socket, substr($data, $offset));
            if ($sent === false || $sent === 0) {
                throw new AttachmentRejected('antivirus_unavailable', 503);
            }
            $offset += $sent;
        }
    }

    private function scan(string $path): void
    {
        $timeout = max(1, min(30, $this->policy['timeout_seconds'] ?? 18));
        $deadline = microtime(true) + $timeout;
        $context = stream_context_create();
        if (str_starts_with($this->policy['socket'], 'tls://')) {
            foreach (['tls_ca', 'tls_cert', 'tls_key'] as $key) {
                if (empty($this->policy[$key]) || !is_file($this->policy[$key]) || is_link($this->policy[$key])) {
                    throw new AttachmentRejected('antivirus_configuration', 503);
                }
            }
            stream_context_set_option($context, ['ssl' => [
                'verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => 'localhost',
                'cafile' => $this->policy['tls_ca'], 'local_cert' => $this->policy['tls_cert'],
                'local_pk' => $this->policy['tls_key'], 'disable_compression' => true,
            ]]);
        }
        $socket = @stream_socket_client($this->policy['socket'], $number, $message, 2, STREAM_CLIENT_CONNECT, $context);
        if ($socket === false) {
            throw new AttachmentRejected('antivirus_unavailable', 503);
        }
        $file = null;
        try {
            stream_set_timeout($socket, $timeout);
            self::writeAll($socket, "zINSTREAM\0", $deadline);
            $file = fopen($path, 'rb');
            if ($file === false) {
                throw new AttachmentRejected('temporary_storage_unavailable', 503);
            }
            while (!feof($file)) {
                $chunk = fread($file, 65536);
                if ($chunk === false) {
                    throw new AttachmentRejected('file_unavailable', 503);
                }
                if ($chunk !== '') {
                    self::writeAll($socket, pack('N', strlen($chunk)) . $chunk, $deadline);
                }
            }
            self::writeAll($socket, pack('N', 0), $deadline);
            $reply = '';
            while (strlen($reply) < 4096 && !str_contains($reply, "\0")) {
                if (microtime(true) >= $deadline) {
                    throw new AttachmentRejected('antivirus_timeout', 503);
                }
                $chunk = @fread($socket, 512);
                if ($chunk === false || $chunk === '') {
                    throw new AttachmentRejected('antivirus_incomplete', 503);
                }
                $reply .= $chunk;
            }
            if (!str_ends_with($reply, "\0") || substr_count($reply, "\0") !== 1) {
                throw new AttachmentRejected('antivirus_incomplete', 503);
            }
            $reply = substr($reply, 0, -1);
            if ($reply === 'stream: OK') {
                return;
            }
            if (preg_match('/^stream: [^\r\n\x00]{1,500} FOUND$/D', $reply)) {
                throw new AttachmentRejected(str_contains($reply, 'Limits.Exceeded') ? 'antivirus_limit' : 'antivirus_detected');
            }
            throw new AttachmentRejected('antivirus_incomplete', 503);
        } finally {
            if (is_resource($file)) {
                fclose($file);
            }
            fclose($socket);
        }
    }

    public function checkPath(string $path, string $name, bool $upload = false, bool $retain = false): array
    {
        $snapshot = null;
        try {
            $extension = $this->filename($name);
            $snapshot = $this->snapshot($path, $upload);
            $this->scan($snapshot['path']);
            $mime = $this->format($snapshot['path'], $extension);
            $snapshot['mime'] = $mime;
            return $snapshot;
        } catch (\Throwable $error) {
            $this->event($error instanceof AttachmentRejected ? $error->reason : 'inspection_error', $snapshot);
            throw $error;
        } finally {
            if (is_array($snapshot) && (!$retain || !isset($snapshot['mime'])) && is_file($snapshot['path'])) {
                unlink($snapshot['path']);
            }
        }
    }

    private function format(string $path, string $extension): string
    {
        $mime = (new \finfo(FILEINFO_MIME_TYPE))->file($path);
        $source = fopen($path, 'rb');
        $head = fread($source, 1024);
        fclose($source);
        if (str_starts_with($head, 'MZ') || str_starts_with($head, "\x7fELF") || str_starts_with($head, '#!') ||
                str_starts_with(ltrim($head), '<?php')) {
            throw new AttachmentRejected('executable_disguised_as_document');
        }
        if ($extension === 'pdf') {
            $data = file_get_contents($path);
            if ($mime !== 'application/pdf' || !preg_match('/^%PDF-[12]\.[0-9]/', $data) ||
                    !str_contains(substr($data, -2048), '%%EOF')) {
                throw new AttachmentRejected('file_content_mismatch');
            }
            $this->pdfNames($data);
            return 'application/pdf';
        }
        if ($extension === 'docx' || $extension === 'pptx') {
            $this->officeZip($path, $extension);
            return $extension === 'docx'
                ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                : 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        }
        if ($extension === 'doc') {
            if (substr($head, 0, 8) !== "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
                throw new AttachmentRejected('file_content_mismatch');
            }
            $this->legacyWord($path);
            return 'application/msword';
        }
        $images = ['png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
                   'gif' => 'image/gif', 'webp' => 'image/webp'];
        if (isset($images[$extension])) {
            $image = @getimagesize($path);
            if ($mime !== $images[$extension] || !$image || ($image['mime'] ?? '') !== $images[$extension] ||
                    $image[0] * $image[1] > 60000000) {
                throw new AttachmentRejected('file_content_mismatch');
            }
            return $images[$extension];
        }
        throw new AttachmentRejected('file_type_not_allowed');
    }

    private function pdfNames(string $data): void
    {
        // A conservative check of visible PDF name tokens, not a full PDF parser.
        // Ignore comments, strings and binary streams: searching raw compressed
        // bytes for short names such as /JS produces false positives.
        $at = 0;
        $length = strlen($data);
        $delimiters = "\x00\x09\x0a\x0c\x0d\x20()<>[]{}/%";
        $blocked = ['JavaScript', 'JS', 'Launch', 'EmbeddedFile', 'RichMedia', 'XFA', 'Encrypt'];
        while ($at < $length) {
            $char = $data[$at];
            if ($char === '%') {
                $at += strcspn($data, "\r\n", $at);
            } elseif ($char === '(') {
                $depth = 1;
                $at++;
                while ($at < $length && $depth) {
                    if ($data[$at] === '\\') {
                        $at += 2;
                        continue;
                    }
                    if ($data[$at] === '(') { $depth++; }
                    if ($data[$at] === ')') { $depth--; }
                    $at++;
                }
            } elseif ($char === '<' && ($data[$at + 1] ?? '') !== '<') {
                $end = strpos($data, '>', $at + 1);
                $at = $end === false ? $length : $end + 1;
            } elseif ($char === '/') {
                $at++;
                $size = strcspn($data, $delimiters, $at);
                $name = preg_replace_callback('/#([0-9a-f]{2})/i', fn ($m) => chr(hexdec($m[1])), substr($data, $at, $size));
                if (in_array($name, $blocked, true)) {
                    throw new AttachmentRejected('active_or_encrypted_pdf');
                }
                $at += $size;
            } elseif (str_contains($delimiters, $char)) {
                $at++;
                if ($char === '<' && ($data[$at] ?? '') === '<') { $at++; }
            } else {
                $size = strcspn($data, $delimiters, $at);
                $token = substr($data, $at, $size);
                $at += max(1, $size);
                if ($token === 'stream') {
                    $end = strpos($data, 'endstream', $at);
                    $at = $end === false ? $length : $end + 9;
                }
            }
        }
    }

    private function officeZip(string $path, string $extension): void
    {
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::RDONLY) !== true) {
            throw new AttachmentRejected('invalid_office_container');
        }
        try {
            if ($zip->numFiles < 2) {
                throw new AttachmentRejected('invalid_office_container');
            }
            if ($zip->numFiles > ($this->policy['max_zip_entries'] ?? 1000)) {
                throw new AttachmentRejected('archive_limit');
            }
            $total = 0;
            $names = [];
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if (!$stat) {
                    throw new AttachmentRejected('invalid_office_container');
                }
                $name = $stat['name'];
                $lower = strtolower($name);
                if (isset($names[$lower]) || preg_match('~(?:^/|\\\\|\x00|(?:^|/)\.\.(?:/|$))~', $name)) {
                    throw new AttachmentRejected('unsafe_archive_path');
                }
                $names[$lower] = true;
                if (($stat['encryption_method'] ?? 0) !== 0) {
                    throw new AttachmentRejected('encrypted_document');
                }
                $total += $stat['size'];
                if ($stat['size'] > 16 * 1024 * 1024 || $total > ($this->policy['max_unpacked_bytes'] ?? 80 * 1024 * 1024) ||
                        $stat['size'] / max(1, $stat['comp_size']) > ($this->policy['max_zip_ratio'] ?? 100)) {
                    throw new AttachmentRejected('archive_limit');
                }
                if (preg_match('~(?:vbaproject|vbadata|/activex/|/embeddings/|(?:^|/)macros/)|\.(exe|dll|com|scr|js|vbs|ps1|hta)$~i', $name)) {
                    throw new AttachmentRejected('macro_or_embedded_object');
                }
                if (str_ends_with($lower, '.rels') || $lower === '[content_types].xml' ||
                        $lower === 'word/document.xml' || $lower === 'ppt/presentation.xml') {
                    $xml = $zip->getFromIndex($i);
                    if ($xml === false || str_contains($xml, '<!DOCTYPE') || str_contains($xml, '<!ENTITY')) {
                        throw new AttachmentRejected('unsafe_office_xml');
                    }
                    $dom = new \DOMDocument();
                    $previous = libxml_use_internal_errors(true);
                    try {
                        if (!$dom->loadXML($xml, LIBXML_NONET)) {
                            throw new AttachmentRejected('invalid_office_xml');
                        }
                    } finally {
                        libxml_clear_errors();
                        libxml_use_internal_errors($previous);
                    }
                    if (stripos($xml, 'macroEnabled') !== false) {
                        throw new AttachmentRejected('macro_or_embedded_object');
                    }
                    if (str_ends_with($lower, '.rels')) {
                        foreach ($dom->getElementsByTagName('Relationship') as $relationship) {
                            if (strcasecmp($relationship->getAttribute('TargetMode'), 'External') === 0 &&
                                    !str_ends_with($relationship->getAttribute('Type'), '/hyperlink')) {
                                throw new AttachmentRejected('external_office_content');
                            }
                        }
                    }
                    if ($lower === 'word/document.xml') {
                        $instructions = '';
                        foreach ($dom->getElementsByTagNameNS('http://schemas.openxmlformats.org/wordprocessingml/2006/main', 'instrText') as $field) {
                            $instructions .= $field->textContent;
                        }
                        if (preg_match('/\b(DDEAUTO|INCLUDETEXT|DDE)\b/i', $instructions)) {
                            throw new AttachmentRejected('active_office_field');
                        }
                    }
                }
            }
            $required = $extension === 'docx' ? 'word/document.xml' : 'ppt/presentation.xml';
            if (!isset($names['[content_types].xml'], $names[$required])) {
                throw new AttachmentRejected('file_content_mismatch');
            }
            $types = $zip->getFromName('[Content_Types].xml');
            $expected = $extension === 'docx'
                ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
                : 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml';
            if ($types === false || !str_contains($types, $expected)) {
                throw new AttachmentRejected('file_content_mismatch');
            }
        } finally {
            $zip->close();
        }
    }

    private function legacyWord(string $path): void
    {
        // Bounded Compound File directory traversal; no macro execution or extraction.
        $data = file_get_contents($path);
        $u32 = static fn (string $bytes, int $at): int => unpack('V', substr($bytes, $at, 4))[1];
        $u16 = static fn (string $bytes, int $at): int => unpack('v', substr($bytes, $at, 2))[1];
        if (strlen($data) < 512 || substr($data, 28, 2) !== "\xfe\xff" ||
                !in_array($u16($data, 30), [9, 12], true)) {
            throw new AttachmentRejected('invalid_legacy_word');
        }
        $size = 1 << $u16($data, 30);
        $sectors = intdiv(strlen($data), $size) - 1;
        $sector = static function (int $id) use ($data, $size, $sectors): string {
            if ($id < 0 || $id >= $sectors) {
                throw new AttachmentRejected('invalid_legacy_word');
            }
            return substr($data, ($id + 1) * $size, $size);
        };
        $fatIds = array_values(unpack('V*', substr($data, 76, 436)));
        $next = $u32($data, 68);
        $visited = [];
        $difatCount = $u32($data, 72);
        if ($difatCount > 512 || $u32($data, 44) > 512) {
            throw new AttachmentRejected('legacy_word_limit');
        }
        for ($i = 0; $i < $difatCount; $i++) {
            if (isset($visited[$next])) {
                throw new AttachmentRejected('invalid_legacy_word');
            }
            $visited[$next] = true;
            $block = $sector($next);
            $fatIds = array_merge($fatIds, array_values(unpack('V*', substr($block, 0, -4))));
            $next = $u32($block, $size - 4);
        }
        $fatIds = array_values(array_filter($fatIds, static fn ($id) => $id !== 0xffffffff));
        if (count($fatIds) !== $u32($data, 44) || count(array_unique($fatIds)) !== count($fatIds)) {
            throw new AttachmentRejected('invalid_legacy_word');
        }
        $fat = [];
        foreach ($fatIds as $id) {
            $fat = array_merge($fat, array_values(unpack('V*', $sector($id))));
        }
        $next = $u32($data, 48);
        $visited = [];
        $word = false;
        while ($next !== 0xfffffffe) {
            if (isset($visited[$next]) || !isset($fat[$next]) || count($visited) > $sectors) {
                throw new AttachmentRejected('invalid_legacy_word');
            }
            $visited[$next] = true;
            $block = $sector($next);
            for ($at = 0; $at < $size; $at += 128) {
                $type = ord($block[$at + 66]);
                if ($type === 0) {
                    continue;
                }
                $length = $u16($block, $at + 64);
                if ($length < 2 || $length > 64 || $length % 2) {
                    throw new AttachmentRejected('invalid_legacy_word');
                }
                $name = strtolower(mb_convert_encoding(substr($block, $at, $length - 2), 'UTF-8', 'UTF-16LE'));
                if (in_array($name, ['vba', 'macros', '_vba_project', 'objectpool', 'encryptedpackage', 'encryptioninfo'], true)) {
                    throw new AttachmentRejected('macro_or_embedded_object');
                }
                $word = $word || ($name === 'worddocument' && $type === 2);
            }
            $next = $fat[$next];
        }
        if (!$word) {
            throw new AttachmentRejected('file_content_mismatch');
        }
    }

    public function serve(string $path, string $filename, bool $inline = false): void
    {
        $snapshot = null;
        try {
            $snapshot = $this->checkPath($path, $filename, false, true);
            // Deliver the exact snapshot that was inspected, not the mutable original.
            header('Content-Type: ' . $snapshot['mime']);
            header('Content-Length: ' . $snapshot['bytes']);
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: private, no-store');
            $encoded = rawurlencode($filename);
            header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') .
                '; filename="' . $encoded . '"; filename*=UTF-8\'\'' . $encoded);
            readfile($snapshot['path']);
        } catch (\Throwable $error) {
            self::deny($error);
        } finally {
            if (is_array($snapshot) && is_file($snapshot['path'])) {
                unlink($snapshot['path']);
            }
        }
    }

    private function event(string $reason, ?array $snapshot): void
    {
        $item = ['time' => gmdate('c'), 'event' => 'attachment_blocked', 'reason' => $reason,
                 'sha256' => $snapshot['sha256'] ?? null, 'bytes' => $snapshot['bytes'] ?? null];
        if (isset($this->policy['event_log'])) {
            @file_put_contents($this->policy['event_log'], json_encode($item) . "\n", FILE_APPEND | LOCK_EX);
        }
        error_log('OJS-Fix attachment blocked: ' . $reason);
    }

    public static function deny(\Throwable $error): void
    {
        $status = $error instanceof AttachmentRejected ? $error->status : 503;
        $reason = $error instanceof AttachmentRejected ? $error->reason : 'inspection_error';
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        $message = $status === 503
            ? 'No se pudo verificar el archivo con el antivirus. Inténtelo nuevamente más tarde.'
            : 'Archivo rechazado por seguridad. Envíe un documento válido, sin macros, objetos incrustados ni contraseña.';
        echo json_encode(['status' => false, 'content' => $message, 'error' => 'ojsFix.' . $reason,
                          'errorMessage' => $message], JSON_UNESCAPED_UNICODE);
        exit;
    }
}
