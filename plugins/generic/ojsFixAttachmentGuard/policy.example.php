<?php
/** MIT. Copy to policy.php, adapt and approve with the protected code baseline. */
return [
    'socket' => 'unix:///run/ojs-fix-journal/scan.sock',
    'private_dir' => '/home/journal/ojs-private',
    'temp_dir' => '/home/journal/tmp/uploads',
    'event_log' => '/home/journal/tmp/ojs-fix-attachments.jsonl',
    'max_bytes' => 20 * 1024 * 1024,
    'timeout_seconds' => 18,
    'allowed_extensions' => ['pdf', 'doc', 'docx', 'pptx', 'png', 'jpg', 'jpeg', 'gif', 'webp'],
    'max_zip_entries' => 1000,
    'max_unpacked_bytes' => 80 * 1024 * 1024,
    'max_zip_ratio' => 100,
];
