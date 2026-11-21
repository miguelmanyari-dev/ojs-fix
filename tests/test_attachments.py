"""Standalone PHP attachment gate tests with a local fake ClamAV daemon."""
import base64
import io
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
import email
import email.policy

ROOT = Path(__file__).resolve().parents[1]
PHP = os.environ.get('PHP_BINARY') or shutil.which('php')
OJS_AUTOLOAD = os.environ.get('OJS_VENDOR_AUTOLOAD')
PDF = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n'
TYPES = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
DOCUMENT = '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Harmless manuscript</w:t></w:r></w:p></w:body></w:document>'


def docx(extra=None, document=DOCUMENT, types=TYPES):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as package:
        package.writestr('[Content_Types].xml', types)
        package.writestr('word/document.xml', document)
        for name, content in (extra or {}).items():
            package.writestr(name, content)
    return output.getvalue()


def legacy_word(macro=False):
    header = bytearray(512)
    header[:8] = bytes.fromhex('d0cf11e0a1b11ae1')
    struct.pack_into('<HHHH', header, 24, 0x3e, 3, 0xfffe, 9)
    struct.pack_into('<I', header, 44, 1)
    struct.pack_into('<I', header, 48, 1)
    struct.pack_into('<II', header, 68, 0xfffffffe, 0)
    header[76:] = struct.pack('<109I', 0, *([0xffffffff] * 108))
    fat = struct.pack('<128I', 0xfffffffd, 0xfffffffe, 0xfffffffe, *([0xffffffff] * 125))
    directory = bytearray(512)
    for index, (name, kind) in enumerate([('Root Entry', 5), ('WordDocument', 2)] + ([('VBA', 1)] if macro else [])):
        encoded = (name + '\0').encode('utf-16le')
        directory[index * 128:index * 128 + len(encoded)] = encoded
        struct.pack_into('<H', directory, index * 128 + 64, len(encoded))
        directory[index * 128 + 66] = kind
    return bytes(header) + fat + directory + bytes(512)


def read_exact(connection, size):
    value = b''
    while len(value) < size:
        part = connection.recv(size - len(value))
        if not part:
            raise OSError('truncated')
        value += part
    return value


@unittest.skipUnless(PHP, 'PHP 8 CLI with zip, fileinfo, dom and mbstring required')
class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.plugin = self.root / 'plugin'
        shutil.copytree(str(ROOT / 'plugins/generic/ojsFixAttachmentGuard'), str(self.plugin))
        self.private = self.root / 'private'
        self.uploads = self.root / 'uploads'
        self.private.mkdir()
        self.uploads.mkdir()
        self.socket_path = str(self.root / 'clam.sock')
        self.policy = {'socket': 'unix://' + self.socket_path, 'private_dir': str(self.private),
                       'temp_dir': str(self.uploads), 'max_bytes': 1024 * 1024,
                       'allowed_extensions': ['pdf', 'doc', 'docx', 'pptx', 'png', 'jpg', 'jpeg', 'gif', 'webp'],
                       'timeout_seconds': 1}
        encoded = base64.b64encode(json.dumps(self.policy).encode()).decode()
        (self.plugin / 'policy.php').write_text("<?php return json_decode(base64_decode('" + encoded + "'), true);")
        self.mode = 'normal'
        self.on_scan = None
        self.stop = threading.Event()
        self.scanner = socket.socket(socket.AF_UNIX)
        self.scanner.bind(self.socket_path)
        self.scanner.listen(8)
        self.scanner.settimeout(0.1)
        self.worker = threading.Thread(target=self.daemon)
        self.worker.start()
        self.driver = self.root / 'driver.php'
        self.driver.write_text('''<?php
require $argv[1] . '/AttachmentGate.php';
$gate = new \\OjsFix\\AttachmentGate($argv[1] . '/policy.php');
$data = json_decode(stream_get_contents(STDIN), true);
try {
 if (($data['operation'] ?? '') === 'serve') {
  ob_start(); $gate->serve($data['path'], $data['name']); $bytes=ob_get_clean();
  echo json_encode(['accepted'=>true, 'body'=>base64_encode($bytes)]);
 } else {
  $result=$gate->checkPath($data['path'],$data['name'],$data['upload'] ?? false);
  echo json_encode(['accepted'=>true,'mime'=>$result['mime'],'sha256'=>$result['sha256']]);
 }
} catch (\\OjsFix\\AttachmentRejected $error) {
 echo json_encode(['accepted'=>false,'reason'=>$error->reason,'status'=>$error->status]);
}''')

    def tearDown(self):
        self.stop.set()
        self.worker.join(2)
        self.scanner.close()
        self.temp.cleanup()

    def daemon(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.scanner.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(1)
                try:
                    assert read_exact(connection, 10) == b'zINSTREAM\0'
                    data = b''
                    while True:
                        size = struct.unpack('!I', read_exact(connection, 4))[0]
                        if not size:
                            break
                        data += read_exact(connection, size)
                    if self.on_scan:
                        self.on_scan()
                    if self.mode == 'disconnect':
                        continue
                    if self.mode == 'error':
                        reply = b'stream: scanner error ERROR\0'
                    elif self.mode == 'partial':
                        reply = b'stream: OK'
                    elif b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in data:
                        reply = b'stream: Eicar-Signature FOUND\0'
                    else:
                        reply = b'stream: OK\0'
                    connection.sendall(reply)
                except (OSError, AssertionError):
                    pass

    def check(self, data, name='paper.pdf', operation='check', upload=False, path=None):
        path = path or ((self.uploads if upload else self.private) / 'fixture')
        if data is not None:
            path.write_bytes(data)
        result = subprocess.run([PHP, str(self.driver), str(self.plugin)],
            input=json.dumps({'path': str(path), 'name': name, 'operation': operation, 'upload': upload}),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def rejected(self, content, name, reason):
        result = self.check(content, name)
        self.assertFalse(result['accepted'], result)
        self.assertEqual(reason, result['reason'])

    def test_accepts_clean_pdf_docx_and_legacy_word(self):
        for data, name in [(PDF, 'paper.pdf'), (docx(), 'paper.docx'), (legacy_word(), 'paper.doc')]:
            with self.subTest(name=name):
                self.assertTrue(self.check(data, name)['accepted'])

    def test_executable_renamed_as_word_or_pdf_rejected(self):
        for name in ('paper.docx', 'paper.doc', 'paper.pdf'):
            with self.subTest(name=name):
                self.rejected(b'MZ harmless test fixture', name, 'executable_disguised_as_document')

    def test_eicar_is_blocked_before_format_checks(self):
        # Standard inert antivirus test marker; never a live malware sample.
        self.rejected(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
                      'paper.docx', 'antivirus_detected')

    def test_double_extension_unicode_and_control_names_rejected(self):
        for name in ('paper.exe.docx', 'paper.pdf.exe', 'paper.docm', '../paper.pdf', 'paper\u202efdp.pdf', 'paper.pdf '):
            with self.subTest(name=name):
                self.assertFalse(self.check(PDF, name)['accepted'])

    def test_ordinary_zip_and_html_are_not_word_documents(self):
        self.rejected(b'<html>harmless</html>', 'paper.doc', 'file_content_mismatch')
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr('readme.txt', 'harmless')
        self.rejected(output.getvalue(), 'paper.docx', 'invalid_office_container')

    def test_docx_macros_embedded_objects_and_external_templates_blocked(self):
        for extra, reason in [({'word/vbaProject.bin': b'harmless'}, 'macro_or_embedded_object'),
                              ({'word/embeddings/oleObject1.bin': b'harmless'}, 'macro_or_embedded_object'),
                              ({'../outside': b'harmless'}, 'unsafe_archive_path')]:
            with self.subTest(extra=extra):
                self.rejected(docx(extra), 'paper.docx', reason)
        rel = '<Relationships><Relationship TargetMode="External" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://example.invalid/template"/></Relationships>'
        self.rejected(docx({'word/_rels/settings.xml.rels': rel}), 'paper.docx', 'external_office_content')

    def test_office_external_hyperlink_is_allowed(self):
        rel = '<Relationships><Relationship TargetMode="External" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org"/></Relationships>'
        self.assertTrue(self.check(docx({'word/_rels/document.xml.rels': rel}), 'paper.docx')['accepted'])

    def test_legacy_word_macro_storage_blocked(self):
        self.rejected(legacy_word(macro=True), 'paper.doc', 'macro_or_embedded_object')

    def test_zip_bomb_and_wrong_main_type_are_blocked(self):
        self.rejected(docx({'word/padding.bin': b'a' * 500000}), 'paper.docx', 'archive_limit')
        self.rejected(docx(types=TYPES.replace('document.main+xml', 'template.main+xml')),
                      'paper.docx', 'file_content_mismatch')

    def test_pdf_active_content_encryption_and_type_mismatch(self):
        for token in (b'/JavaScript', b'/J#61vaScript', b'/Launch', b'/Encrypt', b'/EmbeddedFile'):
            with self.subTest(token=token):
                self.rejected(PDF.replace(b'trailer', token + b' trailer'), 'paper.pdf', 'active_or_encrypted_pdf')
        self.rejected(docx(), 'paper.pdf', 'file_content_mismatch')

    def test_pdf_text_and_binary_streams_do_not_trigger_name_false_positives(self):
        for fragment in (b'2 0 obj\n(/JavaScript is a topic, not an action)\nendobj\n',
                         b'2 0 obj\n<< /Length 18 >>\nstream\nrandom /JS bytes\nendstream\nendobj\n',
                         b'% comment mentioning /Encrypt\n'):
            with self.subTest(fragment=fragment):
                self.assertTrue(self.check(PDF.replace(b'trailer', fragment + b'trailer'))['accepted'])

    def test_scanner_errors_disconnect_and_partial_response_fail_closed(self):
        for mode in ('error', 'disconnect', 'partial'):
            self.mode = mode
            with self.subTest(mode=mode):
                result = self.check(PDF)
                self.assertFalse(result['accepted'])
                self.assertEqual(503, result['status'])

    def test_symlinks_and_oversize_are_rejected(self):
        outside = self.root / 'outside'
        outside.write_bytes(PDF)
        link = self.private / 'link'
        link.symlink_to(outside)
        self.assertFalse(self.check(None, path=link)['accepted'])
        self.assertEqual(413, self.check(b'X' * (1024 * 1024 + 1))['status'])

    def test_delivery_uses_scanned_snapshot(self):
        original = self.private / 'fixture'
        self.on_scan = lambda: original.write_bytes(b'changed after snapshot')
        result = self.check(PDF, operation='serve')
        self.assertEqual(PDF, base64.b64decode(result['body']))
        self.assertEqual([], list(self.uploads.glob('ojs-fix-snapshot-*')))

    def test_legacy_download_hook_does_not_fall_through_on_symlink_escape(self):
        outside = self.root / 'unrelated'
        outside.write_bytes(b'private canary, never deliver')
        link = self.private / 'link.pdf'
        link.symlink_to(outside)
        driver = self.root / 'hook.php'
        driver.write_text('''<?php
namespace PKP\\plugins { class GenericPlugin {} }
namespace PKP\\config { class Config { public static function getVar($a,$b) { return getenv('FIXTURE_PRIVATE'); } } }
namespace { require $argv[1] . '/OjsFixAttachmentGuardPlugin.php';
$plugin = new \\APP\\plugins\\generic\\ojsFixAttachmentGuard\\OjsFixAttachmentGuardPlugin();
$args=[$argv[2],null,false,false,'fixture.pdf'];
$plugin->downloadByPath('FileManager::downloadFile',$args);
echo 'UNEXPECTED_FALLTHROUGH'; }''')
        result = subprocess.run([PHP, str(driver), str(self.plugin), str(link)],
            env=dict(os.environ, FIXTURE_PRIVATE=str(self.private)), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(json.loads(result.stdout)['status'])
        self.assertNotIn('private canary', result.stdout)
        self.assertNotIn('UNEXPECTED_FALLTHROUGH', result.stdout)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL CLI required for ephemeral TLS fixtures')
    def test_mutual_tls_requires_trusted_server_and_client_certificates(self):
        def openssl(arguments):
            result = subprocess.run(['openssl'] + arguments, cwd=str(self.root), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, universal_newlines=True, timeout=8)
            self.assertEqual(0, result.returncode, result.stderr)
        for name in ('ca', 'rogue'):
            openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key',
                     '-out', name + '.pem', '-days', '1', '-subj', '/CN=OJS-Fix-Test-' + name])
        for name, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
            openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key',
                     '-out', name + '.csr', '-subj', '/CN=localhost'])
            (self.root / (name + '.ext')).write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=' + usage +
                '\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
            openssl(['x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                     '-CAcreateserial', '-out', name + '.pem', '-days', '1', '-extfile', name + '.ext'])
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen([sys.executable, str(ROOT / 'tools/scan_proxy.py'),
            '--listen-tls', '127.0.0.1:' + str(port), '--tls-cert', str(self.root / 'server.pem'),
            '--tls-key', str(self.root / 'server.key'), '--tls-ca', str(self.root / 'ca.pem'),
            '--upstream', self.socket_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def policy(ca='ca.pem', cert='client.pem', key='client.key'):
            value = dict(self.policy, socket='tls://127.0.0.1:' + str(port),
                tls_ca=str(self.root / ca), tls_cert=str(self.root / cert), tls_key=str(self.root / key))
            encoded = base64.b64encode(json.dumps(value).encode()).decode()
            (self.plugin / 'policy.php').write_text("<?php return json_decode(base64_decode('" + encoded + "'),true);")
        try:
            for _ in range(50):
                self.assertIsNone(process.poll(), 'TLS proxy failed to start')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.025)
            policy()
            self.assertTrue(self.check(PDF)['accepted'])
            policy(ca='rogue.pem')
            self.assertEqual(503, self.check(PDF)['status'])
            policy(cert='rogue.pem', key='rogue.key')
            self.assertEqual(503, self.check(PDF)['status'])
        finally:
            process.terminate()
            process.wait(timeout=3)

    def inspect_mail(self, data, name='paper.pdf', inline=False):
        path = self.private / 'mail-fixture'
        path.write_bytes(data)
        driver = self.root / 'mail.php'
        driver.write_text('''<?php
require getenv('OJS_VENDOR_AUTOLOAD');
require $argv[1] . '/AttachmentGate.php';
$input=json_decode(stream_get_contents(STDIN),true);
$message=(new \\Symfony\\Component\\Mime\\Email())->from('fixture@example.invalid')->to('reviewer@example.invalid')->text('Harmless body')->attachFromPath($input['path'],$input['name']);
if($input['inline']) {
 $image=new \\Symfony\\Component\\Mime\\Part\\DataPart(base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII='),'pixel.png','image/png');
 $image->asInline();$cid=$image->getContentId();$message->html('<img src="cid:'.$cid.'">')->attachPart($image);
}
try {
 $gate=new \\OjsFix\\AttachmentGate($argv[1].'/policy.php');$gate->checkMailMessage($message);
 file_put_contents($input['path'],'changed after inspection');
 echo json_encode(['accepted'=>true,'mime'=>base64_encode($message->toString())]);
} catch(\\OjsFix\\AttachmentRejected $error){echo json_encode(['accepted'=>false,'reason'=>$error->reason,'status'=>$error->status]);}
''')
        result = subprocess.run([PHP, str(driver), str(self.plugin)],
            input=json.dumps({'path': str(path), 'name': name, 'inline': inline}),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout)

    @unittest.skipUnless(OJS_AUTOLOAD, 'Set OJS_VENDOR_AUTOLOAD to the OJS Composer autoloader for MIME integration tests')
    def test_mail_attachments_are_scanned_and_frozen_without_sending(self):
        result = self.inspect_mail(PDF)
        self.assertTrue(result['accepted'])
        message = email.message_from_bytes(base64.b64decode(result['mime']), policy=email.policy.default)
        attachments = list(message.iter_attachments())
        self.assertEqual(1, len(attachments))
        self.assertEqual(PDF, attachments[0].get_payload(decode=True))

    @unittest.skipUnless(OJS_AUTOLOAD, 'Set OJS_VENDOR_AUTOLOAD for MIME integration tests')
    def test_mail_rejects_antivirus_detection_and_scanner_failure(self):
        result = self.inspect_mail(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE', 'paper.docx')
        self.assertEqual('antivirus_detected', result['reason'])
        self.mode = 'error'
        self.assertEqual(503, self.inspect_mail(PDF)['status'])

    @unittest.skipUnless(OJS_AUTOLOAD, 'Set OJS_VENDOR_AUTOLOAD for MIME integration tests')
    def test_mail_keeps_text_and_valid_inline_images(self):
        result = self.inspect_mail(PDF, inline=True)
        self.assertTrue(result['accepted'])
        message = email.message_from_bytes(base64.b64decode(result['mime']), policy=email.policy.default)
        self.assertTrue(any(part.get_content_type() == 'text/plain' for part in message.walk()))
        images = [part for part in message.walk() if part.get_content_type() == 'image/png']
        self.assertEqual(1, len(images))
        self.assertTrue(images[0].get('Content-ID'))

    def test_real_php_upload_prepend_blocks_before_application(self):
        webroot = self.root / 'web'
        webroot.mkdir()
        (webroot / 'index.php').write_text('<?php echo json_encode(["reached_application"=>true]);')
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen([PHP, '-d', 'upload_tmp_dir=' + str(self.uploads),
            '-d', 'auto_prepend_file=' + str(self.plugin / 'prepend.php'),
            '-S', '127.0.0.1:' + str(port), '-t', str(webroot)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.025)
            def upload(data, name):
                boundary = 'OjsFixHarmlessBoundary'
                body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="uploadedFile"; filename="' + name +
                        '"\r\nContent-Type: application/pdf\r\n\r\n').encode() + data + ('\r\n--' + boundary + '--\r\n').encode()
                request = urllib.request.Request('http://127.0.0.1:' + str(port) + '/index.php', data=body,
                    headers={'Content-Type': 'multipart/form-data; boundary=' + boundary})
                try:
                    response = urllib.request.urlopen(request, timeout=3)
                except urllib.error.HTTPError as error:
                    response = error
                return response.status, json.loads(response.read())
            self.assertEqual((200, {'reached_application': True}), upload(PDF, 'paper.pdf'))
            status, body = upload(b'MZ harmless', 'paper.pdf')
            self.assertEqual(422, status)
            self.assertFalse(body['status'])
            self.assertNotIn('reached_application', body)
            self.mode = 'error'
            self.assertEqual(503, upload(PDF, 'paper.pdf')[0])
        finally:
            process.terminate()
            process.wait(timeout=3)
