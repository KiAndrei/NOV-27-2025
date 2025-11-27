<?php
session_start();
require_once 'config.php';
require_once 'send_password_email.php';
require_once 'audit_logger.php';
require_once 'action_logger_helper.php';
require_once 'color_manager.php';

header('Content-Type: application/json');

function send_json_response(bool $success, string $message, array $extra = []): void
{
    echo json_encode(array_merge(['success' => $success, 'message' => $message], $extra));
    exit;
}

// Ensure the requester is an authenticated admin
if (!isset($_SESSION['admin_name']) || $_SESSION['user_type'] !== 'admin') {
    send_json_response(false, 'Unauthorized request. Please log in as an administrator.');
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_json_response(false, 'Invalid request method.');
}

$surname      = trim($_POST['surname'] ?? '');
$first_name   = trim($_POST['first_name'] ?? '');
$middle_name  = trim($_POST['middle_name'] ?? '');
$name         = trim($surname . ', ' . $first_name . ($middle_name ? ' ' . $middle_name : ''));
$email        = trim($_POST['email'] ?? '');
$confirm_email = trim($_POST['confirm_email'] ?? '');
$phone_number = trim($_POST['phone_number'] ?? '');
$user_type    = $_POST['user_type'] ?? '';
$password     = $_POST['password'] ?? '';
$confirm_password = $_POST['confirm_password'] ?? '';

$errors = [];

if ($surname === '') {
    $errors[] = "Surname is required.";
}

if ($first_name === '') {
    $errors[] = "First name is required.";
}

if ($email === '') {
    $errors[] = "Email is required.";
} elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "Please enter a valid email address.";
} elseif (strpos($email, ' ') !== false) {
    $errors[] = "Email cannot contain spaces.";
}

if ($confirm_email === '') {
    $errors[] = "Confirm email is required.";
} elseif (!filter_var($confirm_email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "Please enter a valid confirm email address.";
} elseif (strpos($confirm_email, ' ') !== false) {
    $errors[] = "Confirm email cannot contain spaces.";
}

if ($email !== $confirm_email) {
    $errors[] = "Email addresses do not match.";
}

if ($phone_number === '') {
    $errors[] = "Phone number is required.";
} elseif (!preg_match('/^\d{11}$/', $phone_number)) {
    $errors[] = "Phone number must be exactly 11 digits.";
}

if ($user_type === '') {
    $errors[] = "User type is required.";
}

// Prevent creating admin accounts through this form
if ($user_type === 'admin') {
    $errors[] = "Admin accounts cannot be created through this interface.";
}

if ($password === '') {
    $errors[] = "Password is required.";
} elseif (strpos($password, ' ') !== false) {
    $errors[] = "Password cannot contain spaces.";
} elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_+={}[\]:";\'<>.,?\/\\|~])[A-Za-z\d!@#$%^&*()\-_+={}[\]:";\'<>.,?\/\\|~]{8,}$/', $password)) {
    $errors[] = "Password must be at least 8 characters, include uppercase and lowercase letters, at least one number, and at least one special character (!@#$%^&*()...etc).";
}

if ($password !== $confirm_password) {
    $errors[] = "Passwords do not match.";
}

if (strpos($confirm_password, ' ') !== false) {
    $errors[] = "Confirm password cannot contain spaces.";
}

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM user_form WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $errors[] = "Email already exists.";
}

if (!empty($errors)) {
    send_json_response(false, implode(' ', $errors));
}

// For employees and attorneys, send email BEFORE creating account
if (in_array($user_type, ['employee', 'attorney'], true)) {
    $email_sent = send_password_email($email, $name, $password, $user_type);
    if (!$email_sent) {
        send_json_response(false, "Failed to send password email to $email. Please verify the address and try again.");
    }
}

$hashed_password = password_hash($password, PASSWORD_DEFAULT);
$first_login_flag = $user_type === 'employee' || $user_type === 'attorney' ? 1 : 0;

$stmt = $conn->prepare("INSERT INTO user_form (name, email, phone_number, password, user_type, first_login, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)");
$stmt->bind_param("sssssii", $name, $email, $phone_number, $hashed_password, $user_type, $first_login_flag, $_SESSION['user_id']);

if (!$stmt->execute()) {
    send_json_response(false, "Database error: " . $stmt->error);
}

$new_user_id = $conn->insert_id;

if (in_array($user_type, ['admin', 'attorney'], true)) {
    $colorManager = new ColorManager($conn);
    $assignedColors = $colorManager->assignUserColors($new_user_id, $user_type);
    if ($assignedColors) {
        error_log("Auto-assigned colors to new $user_type (ID: $new_user_id): {$assignedColors['color_name']}");
    }
}

$auditLogger = new AuditLogger($conn);
$admin_id = $_SESSION['user_id'];
$admin_name = $_SESSION['admin_name'];
$auditLogger->logAction(
    $admin_id,
    $admin_name,
    'admin',
    'User Create',
    'User Management',
    "Created new $user_type account: $name ($email)" . (in_array($user_type, ['employee', 'attorney'], true) ? ' - Email sent successfully' : ''),
    'success',
    'medium'
);

$successMessage = match ($user_type) {
    'employee' => "Employee '$name' has been successfully registered! Password email has been sent to $email.",
    'attorney' => "Attorney '$name' has been successfully registered! Password email has been sent to $email.",
    default     => "User '$name' has been successfully created as $user_type."
};

send_json_response(true, $successMessage, ['user_type' => $user_type]);