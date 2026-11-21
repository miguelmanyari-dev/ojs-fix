<?php
/** MIT. Account-only FPM auto_prepend_file: reject before OJS saves uploads. */
require_once __DIR__ . '/AttachmentGate.php';
if (PHP_SAPI !== 'cli' && !empty($_FILES)) {
    try {
        $gate = new \OjsFix\AttachmentGate(__DIR__ . '/policy.php');
        $gate->checkUploads($_FILES);
    } catch (\Throwable $error) {
        \OjsFix\AttachmentGate::deny($error);
    }
}
