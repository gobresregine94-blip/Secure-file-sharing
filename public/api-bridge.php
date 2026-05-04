<?php
/**
 * api-bridge.php  —  PHP Backend Bridge
 * VaultShare — Secure File Sharing System
 * 
 * This PHP file acts as a server-side proxy/bridge to:
 *   1. Verify JWT tokens from the Node.js server
 *   2. Interact with Firebase REST API
 *   3. Handle server-side session management
 *   4. Generate additional security tokens
 * 
 * Usage: Include via JavaScript fetch() calls or direct form submissions
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ── CONFIGURATION ────────────────────────────
define('AIzaSyAAzbAdq3a0sYrb2CkDwbo5U4u2prTUgRo',   getenv('AIzaSyAAzbAdq3a0sYrb2CkDwbo5U4u2prTUgRo')   ?: 'AIzaSyAAzbAdq3a0sYrb2CkDwbo5U4u2prTUgRo');
define('fileshare-5a45c',getenv('fileshare-5a45c')?: 'fileshare-5a45c');
define('JWT_SECRET',         getenv('JWT_SECRET')         ?: 'your-jwt-secret-here');
define('NODE_API_URL',       getenv('NODE_API_URL')        ?: 'http://localhost:3000/api');

// ── ROUTER ───────────────────────────────────
$method   = $_SERVER['REQUEST_METHOD'];
$path     = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$segments = explode('/', trim($path, '/'));
$action   = end($segments);

switch ($action) {
    case 'login':     handleLogin();    break;
    case 'register':  handleRegister(); break;
    case 'verify':    verifyToken();    break;
    case 'health':    healthCheck();    break;
    default:          proxyToNode();    break;
}

// ── FIREBASE AUTH — LOGIN ─────────────────────
function handleLogin() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendError(405, 'Method not allowed');
        return;
    }

    $body     = json_decode(file_get_contents('php://input'), true);
    $email    = filter_var($body['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $password = $body['password'] ?? '';

    if (!$email || empty($password)) {
        sendError(400, 'Email and password are required');
        return;
    }

    // Call Firebase REST API for sign-in
    $firebaseUrl = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='
                 . AIzaSyAAzbAdq3a0sYrb2CkDwbo5U4u2prTUgRo;

    $payload = json_encode([
        'email'             => $email,
        'password'          => $password,
        'returnSecureToken' => true
    ]);

    $response = httpPost($firebaseUrl, $payload);
    $data     = json_decode($response, true);

    if (isset($data['error'])) {
        $msg = mapFirebaseError($data['error']['message']);
        sendError(401, $msg);
        return;
    }

    // Set server-side session cookie
    $sessionToken = generateSessionToken($data['localId'], $email);
    setcookie('vs_session', $sessionToken, [
        'expires'  => time() + 86400,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => isset($_SERVER['HTTPS'])
    ]);

    sendSuccess([
        'message'     => 'Login successful',
        'idToken'     => $data['idToken'],
        'refreshToken'=> $data['refreshToken'],
        'uid'         => $data['localId'],
        'email'       => $data['email'],
        'displayName' => $data['displayName'] ?? '',
        'expiresIn'   => $data['expiresIn']
    ]);
}

// ── FIREBASE AUTH — REGISTER ──────────────────
function handleRegister() {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendError(405, 'Method not allowed');
        return;
    }

    $body     = json_decode(file_get_contents('php://input'), true);
    $email    = filter_var($body['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $password = $body['password'] ?? '';
    $name     = htmlspecialchars(trim($body['name'] ?? ''));

    if (!$email) { sendError(400, 'Valid email required'); return; }
    if (strlen($password) < 8) { sendError(400, 'Password must be 8+ characters'); return; }
    if (empty($name)) { sendError(400, 'Name is required'); return; }

    // Create Firebase user via REST API
    $firebaseUrl = 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key='
                 . AIzaSyAAzbAdq3a0sYrb2CkDwbo5U4u2prTUgRo;

    $payload = json_encode([
        'email'             => $email,
        'password'          => $password,
        'returnSecureToken' => true
    ]);

    $response = httpPost($firebaseUrl, $payload);
    $data     = json_decode($response, true);

    if (isset($data['error'])) {
        $msg = mapFirebaseError($data['error']['message']);
        sendError(400, $msg);
        return;
    }

    // Update display name
    $updateUrl = 'https://identitytoolkit.googleapis.com/v1/accounts:update?key='
               . AIzaSyAAzbAdq3a0sYrb2CkDwbo5U4u2prTUgRo;
    httpPost($updateUrl, json_encode([
        'idToken'     => $data['idToken'],
        'displayName' => $name,
        'returnSecureToken' => false
    ]));

    sendSuccess([
        'message' => 'Account created successfully',
        'uid'     => $data['localId'],
        'email'   => $data['email'],
        'idToken' => $data['idToken']
    ], 201);
}

// ── VERIFY SESSION TOKEN ──────────────────────
function verifyToken() {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $token      = str_replace('Bearer ', '', $authHeader);

    if (empty($token)) {
        // Check cookie as fallback
        $token = $_COOKIE['vs_session'] ?? '';
    }

    if (empty($token)) {
        sendError(401, 'No token provided');
        return;
    }

    $decoded = verifyJWT($token);
    if (!$decoded) {
        sendError(403, 'Invalid or expired token');
        return;
    }

    sendSuccess(['valid' => true, 'user' => $decoded]);
}

// ── PROXY REQUESTS TO NODE.JS API ────────────
function proxyToNode() {
    $method    = $_SERVER['REQUEST_METHOD'];
    $path      = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $targetUrl = NODE_API_URL . preg_replace('/^\/php-api/', '', $path);

    $headers = ['Content-Type: application/json'];

    // Forward Authorization header
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers[] = 'Authorization: ' . $_SERVER['HTTP_AUTHORIZATION'];
    }

    $body = file_get_contents('php://input');

    $ch = curl_init($targetUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_POSTFIELDS     => $body ?: null,
        CURLOPT_TIMEOUT        => 30
    ]);

    $response    = curl_exec($ch);
    $httpCode    = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    http_response_code($httpCode);
    echo $response;
}

// ── HEALTH CHECK ─────────────────────────────
function healthCheck() {
    sendSuccess([
        'status'    => 'OK',
        'service'   => 'VaultShare PHP Bridge',
        'timestamp' => date('c'),
        'php'       => PHP_VERSION
    ]);
}

// ── HELPERS ───────────────────────────────────

function httpPost(string $url, string $payload): string {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_SSL_VERIFYPEER => true
    ]);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result ?: '{"error":{"message":"NETWORK_ERROR"}}';
}

function generateSessionToken(string $uid, string $email): string {
    $header    = base64_encode(json_encode(['alg'=>'HS256','typ'=>'JWT']));
    $payload   = base64_encode(json_encode([
        'uid'   => $uid,
        'email' => $email,
        'iat'   => time(),
        'exp'   => time() + 86400
    ]));
    $signature = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    $sigB64    = base64_encode($signature);
    return "$header.$payload.$sigB64";
}

function verifyJWT(string $token): ?array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;

    [$header, $payload, $sig] = $parts;
    $expectedSig = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));

    if (!hash_equals($expectedSig, $sig)) return null;

    $data = json_decode(base64_decode($payload), true);
    if (!$data || ($data['exp'] ?? 0) < time()) return null;

    return $data;
}

function mapFirebaseError(string $code): string {
    $map = [
        'EMAIL_EXISTS'             => 'This email is already registered.',
        'INVALID_EMAIL'            => 'Invalid email address.',
        'WEAK_PASSWORD'            => 'Password is too weak.',
        'INVALID_LOGIN_CREDENTIALS'=> 'Invalid email or password.',
        'USER_DISABLED'            => 'This account has been disabled.',
        'TOO_MANY_ATTEMPTS_TRY_LATER' => 'Too many failed attempts. Try later.'
    ];
    return $map[$code] ?? 'Authentication error. Please try again.';
}

function sendSuccess(array $data, int $code = 200): void {
    http_response_code($code);
    echo json_encode(array_merge(['success' => true], $data));
    exit();
}

function sendError(int $code, string $message): void {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $message]);
    exit();
}
?>
