<?php
/** MIT. OJS 3.4 adapter: scan private attachments before returning any bytes. */
namespace APP\plugins\generic\ojsFixAttachmentGuard;

use PKP\config\Config;
use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use OjsFix\AttachmentGate;

require_once __DIR__ . '/AttachmentGate.php';

class OjsFixAttachmentGuardPlugin extends GenericPlugin
{
    public function register($category, $path, $mainContextId = null): bool
    {
        $success = parent::register($category, $path, $mainContextId);
        if ($success && $this->getEnabled()) {
            Hook::add('File::download', [$this, 'download']);
            Hook::add('FileManager::downloadFile', [$this, 'downloadByPath']);
        }
        return $success;
    }

    public function isSitePlugin(): bool { return true; }
    public function getDisplayName(): string { return 'OJS-Fix: protección de archivos adjuntos'; }
    public function getDescription(): string
    {
        return 'Verifica los adjuntos con antivirus y una política de contenido antes de descargarlos. Configuración protegida por el administrador del servidor.';
    }

    public function download(string $hook, array $args): bool
    {
        [$file, $filename, $inline] = $args;
        $path = rtrim(Config::getVar('files', 'files_dir'), '/') . '/' . $file->path;
        try {
            $gate = new AttachmentGate(__DIR__ . '/policy.php');
            $gate->serve($path, $filename, $inline);
        } catch (\Throwable $error) {
            AttachmentGate::deny($error);
        }
        exit;
    }

    public function downloadByPath(string $hook, array $args): bool
    {
        [$path, $mediaType, $inline, $result, $filename] = $args;
        $root = realpath(Config::getVar('files', 'files_dir'));
        $real = realpath($path);
        if ($root !== false && str_starts_with($path, $root . '/') &&
                ($real === false || !str_starts_with($real, $root . '/'))) {
            AttachmentGate::deny(new \OjsFix\AttachmentRejected('invalid_file_location'));
        }
        // OJS exports and code assets outside files_dir retain their normal path.
        if ($root === false || $real === false || !str_starts_with($real, $root . '/')) {
            return false;
        }
        if ($filename === null || pathinfo($filename, PATHINFO_EXTENSION) === '') {
            // Legacy temporary-file downloads omit the original display name.
            $mime = (new \finfo(FILEINFO_MIME_TYPE))->file($real);
            $extensions = ['application/pdf' => 'pdf', 'application/msword' => 'doc',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
                'image/png' => 'png', 'image/jpeg' => 'jpg', 'image/gif' => 'gif', 'image/webp' => 'webp'];
            $filename = 'archivo.' . ($extensions[$mime] ?? 'blocked');
        }
        try {
            $gate = new AttachmentGate(__DIR__ . '/policy.php');
            $gate->serve($path, $filename, (bool) $inline);
        } catch (\Throwable $error) {
            AttachmentGate::deny($error);
        }
        exit;
    }
}
