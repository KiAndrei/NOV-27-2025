<?php
// Disable error reporting to prevent JSON corruption
error_reporting(0);
ini_set('display_errors', 0);

session_start();
require_once 'config.php';

// Check if user is logged in
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_type'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Not authenticated']);
    exit();
}

$user_id = $_SESSION['user_id'];
$user_type = $_SESSION['user_type'];

// Get unread notifications count
$stmt = $conn->prepare("SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = FALSE");
$stmt->bind_param('i', $user_id);
$stmt->execute();
$unread_count = $stmt->get_result()->fetch_assoc()['count'];

// Get recent notifications (last 10)
$stmt = $conn->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10");
$stmt->bind_param('i', $user_id);
$stmt->execute();
$notifications = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Mark notifications as read if requested
if (isset($_POST['mark_read']) && $_POST['mark_read'] === 'true') {
    $stmt = $conn->prepare("UPDATE notifications SET is_read = TRUE WHERE user_id = ? AND is_read = FALSE");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
}

// Mark single notification as read if requested
if (isset($_POST['mark_one']) && $_POST['mark_one'] === 'true' && isset($_POST['id'])) {
    $notification_id = intval($_POST['id']);
    $stmt = $conn->prepare("UPDATE notifications SET is_read = TRUE WHERE id = ? AND user_id = ?");
    $stmt->bind_param('ii', $notification_id, $user_id);
    $stmt->execute();
    
    // Refresh unread count after marking one as read
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = FALSE");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
    $unread_count = $stmt->get_result()->fetch_assoc()['count'];
    
    // Get updated notifications list
    $stmt = $conn->prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10");
    $stmt->bind_param('i', $user_id);
    $stmt->execute();
    $notifications = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'unread_count' => $unread_count,
        'notifications' => $notifications
    ]);
    exit();
}

header('Content-Type: application/json');
echo json_encode([
    'unread_count' => $unread_count,
    'notifications' => $notifications
]);
?> 