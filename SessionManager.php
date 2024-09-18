<?php
/*
   Date: 2024/09/18
   Author: Amin Mohenni
   Telegram Channel: t.me/Dev_AminMohebbi
   Developer Telegram ID: t.me/man_khodam_khodaam
*/

interface EncryptionInterface {
    public function encrypt(string $data): ?string;
    public function decrypt(string $data): ?string;
}

interface StorageInterface {
    public function read(string $id): ?string;
    public function write(string $id, string $data, int $lifetime): bool;
    public function destroy(string $id): bool;
    public function gc(int $maxlifetime): bool;
}

interface LoggerInterface {
    public function log(string $message, string $level = 'info'): void;
}

class DefaultEncryption implements EncryptionInterface {
    private $key;

    public function __construct(string $key) {
        $this->key = $key;
    }

    public function encrypt(string $data): ?string {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            return null;
        }
        return base64_encode($iv . $encrypted);
    }

    public function decrypt(string $data): ?string {
        $decoded = base64_decode($data);
        if ($decoded === false) {
            return null;
        }
        $iv = substr($decoded, 0, 16);
        $encrypted = substr($decoded, 16);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            return null;
        }
        return $decrypted;
    }
}

class FileStorage implements StorageInterface {
    private $savePath;

    public function __construct(string $savePath = null) {
        $this->savePath = $savePath ?: ini_get('session.save_path');
    }

    public function read(string $id): ?string {
        $file = $this->savePath . '/sess_' . $id;
        return file_exists($file) ? file_get_contents($file) : null;
    }

    public function write(string $id, string $data, int $lifetime): bool {
        $file = $this->savePath . '/sess_' . $id;
        return file_put_contents($file, $data) !== false;
    }

    public function destroy(string $id): bool {
        $file = $this->savePath . '/sess_' . $id;
        return @unlink($file);
    }

    public function gc(int $maxlifetime): bool {
        $iterator = new DirectoryIterator($this->savePath);
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isFile() && strpos($fileinfo->getFilename(), 'sess_') === 0) {
                if ($fileinfo->getMTime() + $maxlifetime < time()) {
                    @unlink($fileinfo->getPathname());
                }
            }
        }
        return true;
    }
}

class DatabaseStorage implements StorageInterface {
    private $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function read(string $id): ?string {
        $stmt = $this->pdo->prepare("SELECT data FROM sessions WHERE id = ? AND expires_at > NOW()");
        $stmt->execute([$id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ? $result['data'] : null;
    }

    public function write(string $id, string $data, int $lifetime): bool {
        $expiresAt = date('Y-m-d H:i:s', time() + $lifetime);
        $stmt = $this->pdo->prepare("REPLACE INTO sessions (id, data, expires_at) VALUES (?, ?, ?)");
        return $stmt->execute([$id, $data, $expiresAt]);
    }

    public function destroy(string $id): bool {
        $stmt = $this->pdo->prepare("DELETE FROM sessions WHERE id = ?");
        return $stmt->execute([$id]);
    }

    public function gc(int $maxlifetime): bool {
        $stmt = $this->pdo->prepare("DELETE FROM sessions WHERE expires_at < NOW()");
        return $stmt->execute();
    }
}

class SimpleLogger implements LoggerInterface {
    private $logFile;

    public function __construct(string $logFile) {
        $this->logFile = $logFile;
    }

    public function log(string $message, string $level = 'info'): void {
        $logEntry = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), strtoupper($level), $message);
        file_put_contents($this->logFile, $logEntry, FILE_APPEND);
    }
}

class SessionManager {
    private $sessionName;
    private $sessionLifetime;
    private $path;
    private $domain;
    private $secure;
    private $httponly;
    private $sameSite;
    private $encryption;
    private $storage;
    private $logger;

    public function __construct(
        string $sessionName = 'SECURE_SESSION',
        int $sessionLifetime = 3600,
        EncryptionInterface $encryption = null,
        StorageInterface $storage = null,
        LoggerInterface $logger = null,
        string $path = '/',
        string $domain = null,
        bool $secure = true,
        bool $httponly = true,
        string $sameSite = 'Lax'
    ) {
        $this->sessionName = $sessionName;
        $this->sessionLifetime = $sessionLifetime;
        $this->encryption = $encryption ?? new DefaultEncryption($this->generateEncryptionKey());
        $this->storage = $storage ?? new FileStorage();
        $this->logger = $logger ?? new SimpleLogger(__DIR__ . '/session.log');
        $this->path = $path;
        $this->domain = $domain;
        $this->secure = $secure;
        $this->httponly = $httponly;
        $this->sameSite = $sameSite;

        $this->initialize();
    }

    private function initialize(): void {
        ini_set('session.use_strict_mode', 1);
        ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_lifetime', $this->sessionLifetime);
        ini_set('session.cookie_secure', $this->secure);
        ini_set('session.cookie_httponly', $this->httponly);
        ini_set('session.cookie_samesite', $this->sameSite);
        ini_set('session.hash_function', 'sha256');
        ini_set('session.entropy_length', 32);
        
        session_set_save_handler($this->storage, true);
        session_name($this->sessionName);
        session_set_cookie_params([
            'lifetime' => $this->sessionLifetime,
            'path' => $this->path,
            'domain' => $this->domain,
            'secure' => $this->secure,
            'httponly' => $this->httponly,
            'samesite' => $this->sameSite
        ]);
    }

    public function start(): bool {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return true;
        }

        if ($this->secureSessionStart()) {
            $this->rotateSessionId();
            $this->validateSession();
            return true;
        }

        return false;
    }

    private function secureSessionStart(): bool {
        $sessionStartSuccess = session_start([
            'cookie_lifetime' => $this->sessionLifetime,
            'cookie_secure' => $this->secure,
            'cookie_httponly' => $this->httponly,
            'cookie_samesite' => $this->sameSite,
            'use_strict_mode' => true,
            'use_only_cookies' => true,
            'use_trans_sid' => false,
            'sid_length' => 64,
            'sid_bits_per_character' => 6
        ]);

        if (!$sessionStartSuccess) {
            $this->logger->log("Failed to start session", "error");
            return false;
        }

        return true;
    }

    private function rotateSessionId(): void {
        if (!isset($_SESSION['last_regeneration'])) {
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 300) {
            $this->regenerateSession();
        }
    }

    private function regenerateSession(): void {
        $oldSession = $_SESSION;
        session_regenerate_id(true);
        $_SESSION = $oldSession;
        $_SESSION['last_regeneration'] = time();
    }

    private function validateSession(): void {
        if (!isset($_SESSION['created_at'])) {
            $_SESSION['created_at'] = time();
        } elseif (time() - $_SESSION['created_at'] > $this->sessionLifetime) {
            $this->destroy();
            $this->start();
        }
    }

    public function set(string $key, $value): void {
        $encryptedValue = $this->encryption->encrypt(serialize($value));
        if ($encryptedValue === null) {
            $this->logger->log("Failed to encrypt session data for key: $key", "error");
            return;
        }
        $_SESSION[$key] = $encryptedValue;
    }

    public function get(string $key, $default = null) {
        if (!isset($_SESSION[$key])) {
            return $default;
        }
        $decryptedValue = $this->encryption->decrypt($_SESSION[$key]);
        if ($decryptedValue === null) {
            $this->logger->log("Failed to decrypt session data for key: $key", "error");
            return $default;
        }
        return unserialize($decryptedValue);
    }

    public function delete(string $key): void {
        if (isset($_SESSION[$key])) {
            unset($_SESSION[$key]);
        }
    }

    public function destroy(): bool {
        $_SESSION = [];

        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }

        $result = session_destroy();
        if (!$result) {
            $this->logger->log("Failed to destroy session", "error");
        }
        return $result;
    }

    private function generateEncryptionKey(): string {
        return bin2hex(random_bytes(32));
    }

    public function setFlash(string $key, $value): void {
        $encryptedValue = $this->encryption->encrypt(serialize($value));
        if ($encryptedValue === null) {
            $this->logger->log("Failed to encrypt flash data for key: $key", "error");
            return;
        }
        $_SESSION['_flash'][$key] = $encryptedValue;
    }

    public function getFlash(string $key, $default = null) {
        if (!isset($_SESSION['_flash'][$key])) {
            return $default;
        }
        $decryptedValue = $this->encryption->decrypt($_SESSION['_flash'][$key]);
        if ($decryptedValue === null) {
            $this->logger->log("Failed to decrypt flash data for key: $key", "error");
            return $default;
        }
        $value = unserialize($decryptedValue);
        unset($_SESSION['_flash'][$key]);
        return $value;
    }

    public function hasFlash(string $key): bool {
        return isset($_SESSION['_flash'][$key]);
    }

    public function clearFlash(): void {
        unset($_SESSION['_flash']);
    }

    public function getAllFlash(): array {
        $flash = $_SESSION['_flash'] ?? [];
        $this->clearFlash();
        $decryptedFlash = [];
        foreach ($flash as $key => $value) {
            $decryptedValue = $this->encryption->decrypt($value);
            if ($decryptedValue === null) {
                $this->logger->log("Failed to decrypt flash data for key: $key", "error");
                continue;
            }
            $decryptedFlash[$key] = unserialize($decryptedValue);
        }
        return $decryptedFlash;
    }

    public function close(): void {
        session_write_close();
    }
}

class JWTManager {
    private $secretKey;
    private $algorithm;

    public function __construct(string $secretKey, string $algorithm = 'HS256') {
        $this->secretKey = $secretKey;
        $this->algorithm = $algorithm;
    }

    public function createToken(array $payload, int $expiration = 3600): string {
        $header = [
            'typ' => 'JWT',
            'alg' => $this->algorithm
        ];

        $payload['exp'] = time() + $expiration;

        $base64UrlHeader = $this->base64UrlEncode(json_encode($header));
        $base64UrlPayload = $this->base64UrlEncode(json_encode($payload));

        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $this->secretKey, true);
        $base64UrlSignature = $this->base64UrlEncode($signature);

        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }

    public function verifyToken(string $token): ?array {
        $tokenParts = explode('.', $token);
        if (count($tokenParts) != 3) {
            return null;
        }

        list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = $tokenParts;

        $signature = $this->base64UrlDecode($base64UrlSignature);
        $expectedSignature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $this->secretKey, true);

        if (!hash_equals($expectedSignature, $signature)) {
            return null;
        }

        $payload = json_decode($this->base64UrlDecode($base64UrlPayload), true);

        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return null;
        }

        return $payload;
    }

    private function base64UrlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $data): string {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }
}
