<?php
require 'config.php';
require 'functions.php';

header('Content-Type: application/json');

// Ambil method dan endpoint
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$user_id = getBearerToken(); // User ID diambil dari Authorization header

if (!$user_id) {
    http_response_code(401);
    echo json_encode(['status' => false, 'message' => 'Unauthorized']);
    exit;
}

if ($method === 'POST' && $path === '/api/generate-otp') {
    // Generate OTP
    $otp = generateOtpCode();
    $expired_at = date('Y-m-d H:i:s', strtotime('+5 minutes'));

    // Simpan ke DB
    $stmt = $pdo->prepare("INSERT INTO otps (user_id, otp_code, expired_at) VALUES (?, ?, ?)");
    $stmt->execute([$user_id, $otp, $expired_at]);

    echo json_encode([
        'status' => true,
        'user_id' => $user_id,
        'otp' => $otp,
        'expired_at' => $expired_at
    ]);
}

elseif ($method === 'POST' && $path === '/api/validate-otp') {
    $data = json_decode(file_get_contents('php://input'), true);
    $otp_input = $data['otp'] ?? '';

    if (empty($otp_input)) {
        echo json_encode(['status' => false, 'message' => 'OTP wajib diisi']);
        exit;
    }

    // Cek OTP di DB
    $stmt = $pdo->prepare("SELECT * FROM otps WHERE user_id = ? AND otp_code = ? ORDER BY id DESC LIMIT 1");
    $stmt->execute([$user_id, $otp_input]);
    $otp_data = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$otp_data) {
        echo json_encode(['status' => false, 'message' => 'OTP salah']);
        exit;
    }

    // Cek apakah expired
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
