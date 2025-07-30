<?php
require __DIR__ . '/../config.php';
require __DIR__ . '/../function.php';

date_default_timezone_set('Asia/Jakarta');
header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$basePath = '/test_digivo_php/api/';
$path = str_replace($basePath, '/', $uri);

$user_id = getBearerToken();

if (!$user_id) {
    http_response_code(401);
    echo json_encode(['status' => false, 'message' => 'Unauthorized']);
    exit;
}

if ($method === 'POST' && $path === '/generate-otp') {
    $otp = generateOtpCode();
    $expired_at = date('Y-m-d H:i:s', strtotime('+5 minutes'));
    $stmt = $pdo->prepare("INSERT INTO otps (user_id, otp_code, expired_at) VALUES (?, ?, ?)");
    $stmt->execute([$user_id, $otp, $expired_at]);

    echo json_encode([
        'status' => true,
        'user_id' => $user_id,
        'otp' => $otp,
        'expired_at' => $expired_at
    ]);
}
elseif ($method === 'POST' && $path === '/validate-otp') {
    $data = json_decode(file_get_contents('php://input'), true);
    $otp_input = $data['otp'] ?? '';

    if (empty($otp_input)) {
        echo json_encode(['status' => false, 'message' => 'OTP wajib diisi']);
        exit;
    }

    $stmt = $pdo->prepare("SELECT * FROM otps WHERE user_id = ? AND otp_code = ? ORDER BY id DESC LIMIT 1");
    $stmt->execute([$user_id, $otp_input]);
    $otp_data = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$otp_data) {
        echo json_encode(['status' => false, 'message' => 'OTP salah']);
        exit;
    }

    if (strtotime($otp_data['expired_at']) < time()) {
        echo json_encode(['status' => false, 'message' => 'OTP sudah kadaluarsa']);
        exit;
    }

    echo json_encode(['status' => true, 'message' => 'OTP valid']);
}
else {
    http_response_code(404);
    echo json_encode(['status' => false, 'message' => 'Endpoint tidak ditemukan']);
}
