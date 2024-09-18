# PHP Secure Session Management Class

This repository contains a PHP class that facilitates secure session management using encryption, custom storage mechanisms, and logging. The class integrates encryption for session data, storage interfaces for various backends, and detailed logging to provide a robust and secure solution for handling PHP sessions. 

## Features

- **Encryption**: AES-256-CBC encryption to ensure session data is securely stored.
- **Customizable Storage**: Option to store session data either in the file system or a database.
- **Logging**: Integrated logging mechanism for tracking errors and actions.
- **Session Management**: Secure session start, regeneration, validation, and destruction.
- **Flash Messages**: Temporarily store and retrieve data across requests using flash messages.
- **JSON Web Tokens (JWT)**: Generation and verification of JWT tokens.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/php-secure-session-manager.git
   ```

2. Include the class in your project:
   ```php
   require_once 'SessionManager.php';
   ```

## Usage

### Basic Setup

To use the `SessionManager` class, you need to instantiate it with the necessary parameters. By default, the class uses the file system for storage and a default encryption key.

```php
$sessionManager = new SessionManager();
$sessionManager->start();
```

### Example: Setting and Getting a Session Value

You can set and get session data securely using the `set` and `get` methods. All data is encrypted before storage.

```php
// Set session data
$sessionManager->set('username', 'Amin');

// Get session data
$username = $sessionManager->get('username');
echo $username; // Output: Amin
```

### Example: Using Flash Messages

Flash messages allow you to store data that is available for the next request and automatically removed afterward.

```php
// Set flash message
$sessionManager->setFlash('welcome_message', 'Welcome back, Amin!');

// Get flash message
echo $sessionManager->getFlash('welcome_message'); // Output: Welcome back, Amin!
```

### Example: Custom Encryption

You can provide your own encryption key or implement a custom encryption class by following the `EncryptionInterface`.

```php
$customEncryption = new DefaultEncryption('your-custom-key');
$sessionManager = new SessionManager(encryption: $customEncryption);
$sessionManager->start();
```

### Example: Database Storage

For storing sessions in a database, pass a PDO instance to the `DatabaseStorage` class.

```php
$pdo = new PDO('mysql:host=localhost;dbname=sessions', 'username', 'password');
$storage = new DatabaseStorage($pdo);
$sessionManager = new SessionManager(storage: $storage);
$sessionManager->start();
```

### Example: Logging

The session manager logs errors and information to a file. You can customize the log location by passing a custom `LoggerInterface`.

```php
$logger = new SimpleLogger(__DIR__ . '/custom_log.log');
$sessionManager = new SessionManager(logger: $logger);
$sessionManager->start();
```

### Example: JWT Token Generation

The `JWTManager` class can be used to generate and verify JSON Web Tokens (JWT). This can be useful for stateless authentication.

```php
$jwtManager = new JWTManager('your-secret-key');

// Create a token
$token = $jwtManager->createToken(['user_id' => 1]);

// Verify the token
$payload = $jwtManager->verifyToken($token);
if ($payload) {
    echo 'Valid token for user ID: ' . $payload['user_id'];
} else {
    echo 'Invalid token';
}
```

## Detailed API

### `SessionManager` Class

- `start()`: Starts the session securely.
- `set(string $key, mixed $value)`: Sets a session value.
- `get(string $key, mixed $default = null)`: Gets a session value, returns default if not found.
- `delete(string $key)`: Deletes a session value.
- `destroy()`: Destroys the session and removes the session cookie.
- `setFlash(string $key, mixed $value)`: Sets a flash message.
- `getFlash(string $key, mixed $default = null)`: Gets and removes a flash message.
- `hasFlash(string $key)`: Checks if a flash message exists.
- `clearFlash()`: Clears all flash messages.
- `getAllFlash()`: Retrieves and clears all flash messages.
- `close()`: Closes the session and writes data.

### `EncryptionInterface`

- `encrypt(string $data): ?string`: Encrypts the data.
- `decrypt(string $data): ?string`: Decrypts the data.

### `StorageInterface`

- `read(string $id): ?string`: Reads session data.
- `write(string $id, string $data, int $lifetime): bool`: Writes session data.
- `destroy(string $id): bool`: Deletes session data.
- `gc(int $maxlifetime): bool`: Garbage collector to clean up expired sessions.

### `LoggerInterface`

- `log(string $message, string $level = 'info'): void`: Logs a message.

### `JWTManager`

- `createToken(array $payload, int $expiration = 3600): string`: Creates a JWT token.
- `verifyToken(string $token): ?array`: Verifies a JWT token and returns the payload if valid.

## License

This project is licensed under the MIT License. Feel free to use and modify the code as needed.
