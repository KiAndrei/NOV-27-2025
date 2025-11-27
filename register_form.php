<?php
// Ensure proper session handling
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 0); // Set to 1 if using HTTPS

session_start();
@include 'config.php';
@include 'color_manager.php';

// Prevent caching of register form
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// Check if user is already logged in - redirect to appropriate dashboard
if (isset($_SESSION['admin_name']) && $_SESSION['user_type'] === 'admin') {
    header('Location: admin_dashboard.php');
    exit();
} elseif (isset($_SESSION['attorney_name']) && $_SESSION['user_type'] === 'attorney') {
    header('Location: attorney_dashboard.php');
    exit();
} elseif (isset($_SESSION['employee_name']) && $_SESSION['user_type'] === 'employee') {
    header('Location: employee_dashboard.php');
    exit();
} elseif (isset($_SESSION['client_name']) && $_SESSION['user_type'] === 'client') {
    header('Location: client_dashboard.php');
    exit();
}


// Handle canceling OTP verification and going back to registration
if (isset($_POST['cancel_otp'])) {
    unset($_SESSION['pending_registration']);
    unset($_SESSION['show_otp_modal']);
    // Don't set error message since we're handling it client-side now
    // Persist session changes immediately and return a simple response
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    header('Content-Type: text/plain');
    echo 'OK';
    exit();
}

// Handle resending OTP
if (isset($_POST['resend_otp']) && isset($_SESSION['pending_registration'])) {
    $pending = $_SESSION['pending_registration'];
    
    // Generate new OTP
    $new_otp = (string)rand(100000, 999999); // Ensure OTP is stored as string
    $_SESSION['pending_registration']['otp'] = $new_otp;
    $_SESSION['pending_registration']['otp_expires'] = time() + 60; // 1 minute
    
    // Release the session write lock before sending email to avoid blocking concurrent requests
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    
    // Send new OTP email
    require_once 'send_otp_email.php';
    if (send_otp_email($pending['email'], $new_otp)) {
        header('Content-Type: text/plain');
        echo 'OK';
    } else {
        header('Content-Type: text/plain');
        echo 'ERROR';
    }
    exit();
}

// Handle OTP verification
if (isset($_POST['verify_otp']) && isset($_SESSION['pending_registration'])) {
    $input_otp = trim($_POST['otp'] ?? '');
    $pending = $_SESSION['pending_registration'];
    
    
    // Validate that we have all required data
    if (!isset($pending['otp']) || !isset($pending['email']) || !isset($pending['password'])) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Registration data corrupted. Please register again.']);
        exit();
    }
    
    if (time() > $pending['otp_expires']) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'OTP expired. Please click Resend OTP to get a new code.']);
        exit();
    } elseif ((string)$input_otp === (string)$pending['otp']) {
        // Insert user
        $hashed_password = password_hash($pending['password'], PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO user_form(name, email, phone_number, password, user_type) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param('sssss', $pending['name'], $pending['email'], $pending['phone'], $hashed_password, $pending['user_type']);
        if ($stmt->execute()) {
            $new_user_id = $conn->insert_id; // Get the ID of the newly created user
            
            // Automatically assign colors for admin and attorney users
            if ($pending['user_type'] === 'admin' || $pending['user_type'] === 'attorney') {
                $colorManager = new ColorManager($conn);
                $assignedColors = $colorManager->assignUserColors($new_user_id, $pending['user_type']);
                
                if ($assignedColors) {
                    error_log("Auto-assigned colors to new {$pending['user_type']} (ID: $new_user_id): {$assignedColors['color_name']}");
                }
            }
            
            unset($_SESSION['pending_registration']);
            unset($_SESSION['show_otp_modal']);
            $_SESSION['success'] = 'Registration successful! You can now login.';
            // Force session write before response
            session_write_close();
            
            // Return JSON response for AJAX handling
            header('Content-Type: application/json');
            echo json_encode(['status' => 'success', 'message' => 'Registration successful!', 'redirect' => 'login_form.php']);
            exit();
        } else {
            header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => 'Registration failed. Please try again.']);
            exit();
        }
    } else {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Invalid OTP. Please check your email and try again.']);
        exit();
    }
}

// Handle registration form submission
if (isset($_POST['submit'])) {
    $lastname = mysqli_real_escape_string($conn, $_POST['lastname']);
    $firstname = mysqli_real_escape_string($conn, $_POST['firstname']);
    $middlename = mysqli_real_escape_string($conn, $_POST['middlename']);
    
    // Allow spaces in name fields for proper names
    // Removed space restrictions to allow names like "De La Cruz", "Van Der Berg", etc.
    
    $name = trim($lastname . ', ' . $firstname . ' ' . $middlename); // Format: Lastname, Firstname Middlename
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $phone = mysqli_real_escape_string($conn, $_POST['phone']);
    $pass = $_POST['password'];
    $cpass = $_POST['cpassword'];
    $user_type = 'client'; // Only clients can register through this form

    // Phone number validation (server-side)
    if (!preg_match('/^\d{11}$/', $phone)) {
        $_SESSION['error'] = "Phone number must be exactly 11 digits.";
        header("Location: register_form.php");
        exit();
    }

    // Email validation (server-side) - accepts any valid email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error'] = "Please enter a valid email address.";
        header("Location: register_form.php");
        exit();
    }
    
    // Check for spaces in email
    if (strpos($email, ' ') !== false) {
        $_SESSION['error'] = "Email cannot contain spaces.";
        header("Location: register_form.php");
        exit();
    }

    // Password requirements check (server-side)
    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%\^&*()_\-+={}\[\]:;"\'<>,.?\/~`|\\\\])[A-Za-z\d!@#$%\^&*()_\-+={}\[\]:;"\'<>,.?\/~`|\\\\]{8,}$/', $pass)) {
        $_SESSION['error'] = "Password must be at least 8 characters, include uppercase and lowercase letters, at least one number, and at least one allowed special character (! @ # $ % ^ & * ( ) _ + - = { } [ ] : ; \" ' < > , . ? / ~ ` | \\).";
        header("Location: register_form.php");
        exit();
    }
    
    // Check for spaces in password
    if (strpos($pass, ' ') !== false) {
        $_SESSION['error'] = "Password cannot contain spaces.";
        header("Location: register_form.php");
        exit();
    }
    
    // Check for spaces in confirm password
    if (strpos($cpass, ' ') !== false) {
        $_SESSION['error'] = "Confirm password cannot contain spaces.";
        header("Location: register_form.php");
        exit();
    }

    // Password match check
    if ($pass != $cpass) {
        $_SESSION['error'] = "Passwords do not match!";
        header("Location: register_form.php");
        exit();
    }

    // Check if user already exists (email only)
    $select = "SELECT * FROM user_form WHERE email = ?";
    $stmt = mysqli_prepare($conn, $select);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) > 0) {
        $_SESSION['error'] = "User already exists!";
        header("Location: register_form.php");
        exit();
    }

    // OTP logic
    require_once __DIR__ . '/vendor/autoload.php';
    $otp = (string)rand(100000, 999999); // Ensure OTP is stored as string
    $_SESSION['pending_registration'] = [
        'name' => $name,
        'email' => $email,
        'phone' => $phone,
        'password' => $pass,
        'user_type' => $user_type,
        'otp' => $otp,
        'otp_expires' => time() + 60 // 1 minute
    ];
    // Send OTP email and ensure it succeeds before showing OTP modal
    require_once 'send_otp_email.php';
    $otpSent = send_otp_email($email, $otp);
    if ($otpSent) {
        $_SESSION['show_otp_modal'] = true;
    } else {
        // If sending failed, clear pending registration to avoid confusion and show error
        unset($_SESSION['pending_registration']);
        $_SESSION['error'] = 'We could not send the OTP to your email. Please check your email address or try again later.';
        header('Location: register_form.php');
        exit();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register Form</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Poppins', sans-serif;
        }

        body {
            display: flex;
            min-height: 100vh;
            background: #f5f5f5;
        }

        .left-container {
            width: 45%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            padding: 20px;
            position: relative;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.3);
        }

        .title-container {
            display: flex;
            align-items: center;
            position: absolute;
            top: 20px;
            left: 30px;
        }

        .title-container img {
            width: 45px;
            height: 45px;
            margin-right: 8px;
        }

        .title {
            font-size: 24px;
            font-weight: 600;
            color: #ffffff;
            letter-spacing: 1px;
        }

        .header-container {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 15px;
            gap: 6px;
            margin-top: 50px;
        }

        .header-container img {
            width: 35px;
            height: 35px;
        }

        .law-office-title {
            margin-top: 0;
            text-align: center;
            font-size: 24px;
            font-weight: 800;
            color: #ffffff;
            font-family: "Playfair Display", serif;
            letter-spacing: 1.8px;
            text-shadow: 0 3px 8px rgba(0, 0, 0, 0.5);
            line-height: 1.2;
        }

        .form-header {
            font-size: 22px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 15px;
            color: #ffffff;
        }

        .form-container {
            width: 100%;
            max-width: 380px;
            margin: 0 auto;
        }

        .form-container label {
            font-size: 12px;
            font-weight: 500;
            display: block;
            margin: 8px 0 2px;
            color: #ffffff;
            text-align: left;
        }

        .form-container input, .form-container select {
            width: 100%;
            padding: 8px 10px;
            font-size: 13px;
            border: none;
            border-bottom: 2px solid rgba(255, 255, 255, 0.3);
            background: transparent;
            color: #ffffff;
            outline: none;
            transition: all 0.3s ease;
        }

        .form-container input:focus, .form-container select:focus {
            border-bottom: 2px solid #ffffff;
        }

        .form-container input::placeholder {
            color: rgba(255, 255, 255, 0.6);
        }

        .form-container select option {
            background: #5D0E26;
            color: #ffffff;
        }

        .password-container {
            position: relative;
            width: 100%;
        }

        .password-container i {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255, 255, 255, 0.7);
            cursor: pointer;
            transition: color 0.3s ease;
        }

        .password-container i:hover {
            color: #ffffff;
        }

        .form-container .form-btn {
            background: #ffffff;
            color: #5D0E26;
            border: none;
            cursor: pointer;
            padding: 10px;
            font-size: 14px;
            font-weight: 600;
            width: 100%;
            margin-top: 15px;
            border-radius: 8px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .form-container .form-btn:hover {
            background: #f8f8f8;
            color: #8B1538;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
        }

        .right-container {
            width: 55%;
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            color: #5D0E26;
            text-align: center;
            padding: 20px;
            background: #ffffff;
            background-image: url('images/atty3.jpg');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            backdrop-filter: blur(5px);
            position: relative;
        }

        .right-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url('images/atty3.jpg');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            filter: blur(3px);
            z-index: -1;
        }

        /* Professional Modal Alert System */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(93, 14, 38, 0.85);
            backdrop-filter: blur(8px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            animation: fadeIn 0.3s ease;
        }

        #termsModal .modal-alert.terms-modal {
            background: #fff;
            max-width: 520px;
            width: 90%;
            color: #333;
        }

        #termsModal .modal-header {
            background: #fff;
            color: #5D0E26;
            border-bottom: 1px solid #eee;
        }

        #termsModal .modal-header h2 {
            margin-bottom: 6px;
            font-size: 22px;
        }

        #termsModal .modal-header p {
            color: #8B1538;
            font-size: 14px;
        }

        #termsModal .modal-body {
            padding: 0;
        }

        .terms-scroll {
            max-height: 60vh;
            overflow-y: auto;
            padding: 25px 28px;
        }

        .terms-scroll::-webkit-scrollbar {
            width: 6px;
        }

        .terms-scroll::-webkit-scrollbar-thumb {
            background: rgba(93, 14, 38, 0.3);
            border-radius: 3px;
        }

        .terms-intro {
            background: #f9f9f9;
            border: 1px solid #eee;
            padding: 14px 16px;
            border-radius: 8px;
            font-size: 14px;
            line-height: 1.5;
            margin-bottom: 18px;
        }

        #termsModal .modal-body,
        #termsModal .modal-body * {
            text-align: left;
        }

        .terms-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .terms-list li {
            border-bottom: 1px solid #f0f0f0;
            padding: 12px 0;
        }

        .terms-list li:last-child {
            border-bottom: none;
        }

        .terms-list h4 {
            color: #5D0E26;
            font-size: 15px;
            margin-bottom: 6px;
            font-weight: 600;
        }

        .terms-list p {
            font-size: 13px;
            color: #555;
            line-height: 1.5;
        }

        .terms-checkbox {
            margin-top: 18px;
            padding: 12px 15px;
            border-radius: 8px;
            background: #fffaf4;
            border: 1px solid #ffd9c7;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
        }

        .terms-checkbox input[type="checkbox"] {
            width: 16px;
            height: 16px;
            accent-color: #5D0E26;
        }

        #termsModal .modal-footer {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 18px 25px 24px;
        }

        #termsModal .modal-footer .accept-button {
            min-width: 160px;
            font-size: 14px;
            padding: 10px 22px;
        }

        .modal-alert {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 0;
            max-width: 450px;
            width: 90%;
            position: relative;
            animation: modalSlideIn 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            overflow: hidden;
        }

        .modal-alert::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
        }

        .modal-header {
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: white;
            padding: 25px 30px 20px;
            text-align: center;
            position: relative;
        }

        .modal-header::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 3px;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 2px;
        }

        .modal-title {
            font-family: 'Playfair Display', serif;
            font-size: 24px;
            font-weight: 700;
            margin: 0 0 8px 0;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }

        .modal-subtitle {
            font-size: 16px;
            font-weight: 500;
            opacity: 0.9;
            margin: 0;
        }

        .modal-body {
            padding: 30px;
            text-align: center;
        }

        .modal-message {
            font-size: 18px;
            font-weight: 600;
            color: #5D0E26;
            margin: 0 0 12px 0;
            line-height: 1.4;
        }

        .modal-subtext {
            font-size: 14px;
            color: #666;
            margin: 0 0 25px 0;
            line-height: 1.5;
        }

        .modal-button {
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: white;
            border: none;
            padding: 14px 35px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);
            min-width: 120px;
        }

        .modal-button:hover {
            background: linear-gradient(135deg, #8B1538, #5D0E26);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(93, 14, 38, 0.4);
        }

        .modal-button:active {
            transform: translateY(0);
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes modalSlideIn {
            from {
                opacity: 0;
                transform: scale(0.9) translateY(-30px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        /* Legacy error popup for backward compatibility */
        .error-popup {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: #ff6b6b;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
            z-index: 9999;
            width: 90%;
            max-width: 400px;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                transform: translate(-50%, -20px);
                opacity: 0;
            }
            to {
                transform: translate(-50%, 0);
                opacity: 1;
            }
        }

        .error-popup p {
            margin: 0;
            font-size: 14px;
        }

        .error-popup button {
            background: white;
            border: none;
            padding: 8px 15px;
            color: #ff6b6b;
            font-weight: 500;
            margin-top: 10px;
            cursor: pointer;
            border-radius: 4px;
            transition: background 0.3s ease;
        }

        .error-popup button:hover {
            background: #f0f0f0;
        }


        /* Disabled button styles */
        button:disabled {
            opacity: 0.6 !important;
            cursor: not-allowed !important;
            pointer-events: none;
        }

        .login-box h1 {
            font-size: 48px;
            font-weight: 700;
            color: #5D0E26;
            margin-bottom: 20px;
            line-height: 1.3;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            position: relative;
            overflow: hidden;
        }

        .mirror-shine {
            position: relative;
            display: inline-block;
            background: linear-gradient(
                90deg,
                #5D0E26 0%,
                #5D0E26 45%,
                #ffffff 50%,
                #5D0E26 55%,
                #5D0E26 100%
            );
            background-size: 200% 100%;
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: mirrorShine 3s ease-in-out infinite;
        }

        @keyframes mirrorShine {
            0% {
                background-position: -100% 0;
            }
            100% {
                background-position: 100% 0;
            }
        }

        .login-btn {
            display: inline-block;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: white;
            text-decoration: none;
            padding: 18px 40px;
            font-size: 20px;
            font-weight: 600;
            border-radius: 8px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(93, 14, 38, 0.4);
        }

        .login-btn:hover {
            background: linear-gradient(135deg, #8B1538, #5D0E26);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(93, 14, 38, 0.5);
        }

        .back-button {
            position: absolute;
            top: 20px;
            right: 30px;
            background: rgba(255, 255, 255, 0.95);
            color: #5D0E26;
            text-decoration: none;
            padding: 12px 25px;
            font-size: 15px;
            font-weight: 600;
            border-radius: 8px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
            display: flex;
            align-items: center;
            gap: 8px;
            z-index: 100;
        }

        .back-button:hover {
            background: #ffffff;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
        }

        .back-button i {
            font-size: 16px;
        }

        @media (max-width: 1024px) {
            .left-container {
                width: 50%;
            }

            .right-container {
                width: 50%;
            }

            .law-office-title {
                font-size: 22px;
            }
        }

        @media (max-width: 768px) {
            body {
                flex-direction: column;
            }

            .left-container, .right-container {
                width: 100%;
                padding: 40px 20px;
                min-height: auto;
            }

            .left-container {
                padding: 40px 20px 50px;
            }

            .right-container {
                padding: 60px 20px;
                min-height: 50vh;
            }

            .title-container {
                left: 20px;
                top: 15px;
            }

            .title-container img {
                width: 40px;
                height: 40px;
            }

            .title {
                font-size: 20px;
            }

            .law-office-title {
                font-size: 22px;
                margin-top: 0;
            }

            .header-container img {
                width: 32px;
                height: 32px;
            }

            .form-header {
                font-size: 22px;
                margin-bottom: 20px;
            }

            .form-container {
                max-width: 100%;
            }

            .form-container label {
                font-size: 12px;
                margin: 10px 0 3px;
            }

            .form-container input, .form-container select {
                padding: 10px 12px;
                font-size: 14px;
            }

            .form-container .form-btn {
                padding: 12px;
                font-size: 15px;
                margin-top: 18px;
            }

            .login-box h1 {
                font-size: 34px;
            }

            .login-btn {
                padding: 16px 35px;
                font-size: 18px;
            }

            .back-button {
                top: 15px;
                right: 20px;
                padding: 10px 20px;
                font-size: 14px;
            }

            /* Modal responsive */
            .modal-alert {
                max-width: 90%;
                width: 90%;
            }

            .modal-title {
                font-size: 22px;
            }

            .modal-subtitle {
                font-size: 15px;
            }

            .modal-message {
                font-size: 16px;
            }

            .modal-subtext {
                font-size: 13px;
            }

            .modal-button {
                padding: 12px 30px;
                font-size: 15px;
            }

            /* OTP Modal */
            .otp-modal > div {
                max-width: 90% !important;
                width: 90% !important;
                padding: 30px 25px !important;
            }

            /* Password requirements list */
            .form-container ul {
                font-size: 11px !important;
            }
        }

        @media (max-width: 480px) {
            .left-container {
                padding: 35px 15px 40px;
            }

            .right-container {
                padding: 50px 15px;
                min-height: 45vh;
            }

            .title-container {
                left: 15px;
                top: 12px;
            }

            .title-container img {
                width: 35px;
                height: 35px;
            }

            .title {
                font-size: 18px;
            }

            .header-container {
                margin-bottom: 20px;
                gap: 5px;
            }

            .header-container img {
                width: 30px;
                height: 30px;
            }

            .law-office-title {
                font-size: 18px;
                margin-top: 0;
            }

            .form-header {
                font-size: 20px;
                margin-bottom: 18px;
            }

            .form-container label {
                font-size: 11px;
                margin: 8px 0 2px;
            }

            .form-container input, .form-container select {
                font-size: 13px;
                padding: 9px 10px;
            }

            .password-container i {
                right: 10px;
                font-size: 13px;
            }

            .form-container .form-btn {
                padding: 11px;
                font-size: 14px;
                margin-top: 15px;
            }

            .login-box h1 {
                font-size: 26px;
                margin-bottom: 15px;
            }

            .login-btn {
                padding: 14px 28px;
                font-size: 16px;
            }

            .back-button {
                top: 12px;
                right: 15px;
                padding: 8px 16px;
                font-size: 13px;
                gap: 5px;
            }

            .back-button i {
                font-size: 14px;
            }

            /* Modal responsive */
            .modal-alert {
                max-width: 95%;
                width: 95%;
                border-radius: 12px;
            }

            .modal-header {
                padding: 20px 20px 15px;
            }

            .modal-title {
                font-size: 20px;
                margin-bottom: 6px;
            }

            .modal-subtitle {
                font-size: 14px;
            }

            .modal-body {
                padding: 20px;
            }

            .modal-message {
                font-size: 15px;
                margin-bottom: 10px;
            }

            .modal-subtext {
                font-size: 12px;
                margin-bottom: 20px;
            }

            .modal-button {
                padding: 11px 25px;
                font-size: 14px;
            }

            /* OTP Modal */
            .otp-modal > div {
                max-width: 95% !important;
                width: 95% !important;
                padding: 25px 20px !important;
            }

            .otp-modal h2 {
                font-size: 26px !important;
                margin-bottom: 12px !important;
            }

            .otp-modal h3 {
                font-size: 19px !important;
            }

            .otp-modal input[name="otp"] {
                padding: 13px !important;
                font-size: 16px !important;
            }

            .otp-modal button[type="button"] {
                padding: 14px !important;
                font-size: 15px !important;
            }

            .otp-modal > div > div:last-child button {
                font-size: 12px !important;
                padding: 6px 12px !important;
                margin-right: 8px !important;
            }

            /* Password requirements list */
            .form-container ul {
                font-size: 10px !important;
                margin-bottom: 6px !important;
                padding-left: 16px !important;
            }

            .form-container ul li {
                margin-bottom: 1px;
            }

            /* Name input fields - make them stack on very small screens */
            .form-container > form > label + div[style*="display: flex"] {
                flex-direction: column !important;
                gap: 5px !important;
            }

            .form-container > form > label + div[style*="display: flex"] input {
                width: 100% !important;
            }

        }

        @media (max-width: 360px) {
            .left-container {
                padding: 30px 12px 35px;
            }

            .right-container {
                padding: 40px 12px;
            }

            .title {
                font-size: 16px;
            }

            .title-container img {
                width: 32px;
                height: 32px;
            }

            .law-office-title {
                font-size: 18px;
                margin-top: 0;
            }

            .header-container img {
                width: 28px;
                height: 28px;
            }

            .form-header {
                font-size: 18px;
            }

            .login-box h1 {
                font-size: 22px;
            }

            .login-btn {
                padding: 12px 24px;
                font-size: 15px;
            }

            .back-button {
                padding: 7px 14px;
                font-size: 12px;
            }

            .form-container input, .form-container select {
                font-size: 12px;
                padding: 8px 10px;
            }

            .form-container .form-btn {
                padding: 10px;
                font-size: 13px;
            }

            .form-container ul {
                font-size: 9px !important;
            }
        }

        /* Touch improvements for mobile */
        @media (hover: none) and (pointer: coarse) {
            .form-container input,
            .form-container select,
            .form-container .form-btn,
            .login-btn,
            .back-button,
            .modal-button {
                -webkit-tap-highlight-color: transparent;
            }

            .password-container i {
                padding: 10px;
            }
        }

        /* Prevent tiny page scrollbar on desktop while allowing mobile scroll */
        @media (min-width: 769px) {
            html, body { height: 100%; overflow: hidden; }
            .left-container, .right-container { height: 100vh; overflow: hidden; }
        }

        /* Allow scroll on mobile for long forms */
        @media (max-width: 768px) {
            html, body {
                height: auto;
                overflow-y: auto;
            }
            
            .left-container {
                overflow-y: auto;
            }
        }
        /* Data Privacy Waiver Modal Styles */
        #dataPrivacyModal {
            display: none;
            position: fixed;
            z-index: 10001;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(8px);
        }

        #dataPrivacyModalContent {
            max-width: 700px;
            max-height: 70vh;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            position: relative;
            top: 50%;
            transform: translateY(-50%);
            margin: 0 auto;
            animation: slideDownFromTop 0.5s ease-out;
        }

        #dataPrivacyModal .modal-header {
            background: white;
            color: #333;
            padding: 20px 25px 15px;
            border-radius: 12px 12px 0 0;
            border-bottom: 1px solid #e9ecef;
        }

        #dataPrivacyModal .modal-header h2 {
            margin: 0;
            font-size: 1.2rem;
            font-weight: 600;
            color: #5D0E26;
        }

        #dataPrivacyModal .modal-body {
            padding: 0;
            background: white;
            max-height: calc(70vh - 80px);
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: #ccc transparent;
        }

        #dataPrivacyModal .modal-body::-webkit-scrollbar {
            width: 6px;
        }

        #dataPrivacyModal .modal-body::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 3px;
        }

        #dataPrivacyModal .modal-body::-webkit-scrollbar-thumb {
            background: #5D0E26;
            border-radius: 3px;
        }

        #dataPrivacyModal .modal-body::-webkit-scrollbar-thumb:hover {
            background: #8B1538;
        }

        #dataPrivacyModal .modal-content-inner {
            padding: 20px 25px;
            text-align: left;
        }

        #dataPrivacyModal .office-header {
            text-align: center;
            margin-bottom: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 6px;
        }

        #dataPrivacyModal .office-logo {
            width: 50px;
            height: 50px;
            background: #5D0E26;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 10px;
        }

        #dataPrivacyModal .office-logo img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            border-radius: 50%;
        }

        #dataPrivacyModal .office-title {
            color: #5D0E26;
            margin: 0;
            font-size: 1.1rem;
            font-weight: 600;
            text-align: center;
            width: 100%;
        }

        #dataPrivacyModal .office-subtitle {
            color: #666;
            margin: 5px 0 0;
            font-size: 0.85rem;
            text-align: center;
            width: 100%;
        }

        #dataPrivacyModal .important-notice {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 15px;
            text-align: left;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 6px;
        }

        #dataPrivacyModal .important-notice h4 {
            color: #5D0E26;
            margin: 0 0 8px;
            font-size: 0.9rem;
            font-weight: 600;
        }

        #dataPrivacyModal .important-notice p {
            margin: 0;
            color: #555;
            font-size: 0.85rem;
            line-height: 1.4;
        }

        #dataPrivacyModal .section {
            margin-bottom: 15px;
            text-align: left;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 6px;
        }

        #dataPrivacyModal .section h4 {
            color: #333;
            margin: 0 0 10px;
            font-size: 0.9rem;
            font-weight: 600;
        }

        #dataPrivacyModal .section p {
            margin: 0 0 8px;
            color: #555;
            font-size: 0.8rem;
            line-height: 1.4;
        }

        #dataPrivacyModal .section ul {
            margin: 0 0 8px 15px;
            color: #555;
            font-size: 0.8rem;
            line-height: 1.4;
        }

        #dataPrivacyModal .section li {
            margin-bottom: 4px;
        }

        #dataPrivacyModal .consent-section {
            background: #fff3cd;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 15px;
            border: 1px solid #ffeaa7;
            text-align: left;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            gap: 6px;
        }

        #dataPrivacyModal .consent-section h4 {
            color: #856404;
            margin: 0 0 8px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        #dataPrivacyModal .consent-section p {
            margin: 0 0 10px;
            color: #856404;
            font-size: 0.8rem;
            line-height: 1.4;
        }

        #dataPrivacyModal .checkbox-container {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        #dataPrivacyModal .checkbox-container input[type="checkbox"] {
            width: 16px;
            height: 16px;
            accent-color: #5D0E26;
        }

        #dataPrivacyModal .checkbox-container label {
            color: #856404;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
        }

        #dataPrivacyModal .modal-footer {
            padding: 15px 25px;
            background: white;
            border-top: 1px solid #e9ecef;
            border-radius: 0 0 12px 12px;
            display: flex;
            justify-content: center;
        }

        #dataPrivacyModal .accept-button {
            background: #ccc;
            color: #666;
            border: none;
            padding: 10px 24px;
            border-radius: 6px;
            cursor: not-allowed;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.3s;
        }

        #dataPrivacyModal .accept-button:not(:disabled) {
            background: #5D0E26;
            color: white;
            cursor: pointer;
        }

        #dataPrivacyModal .accept-button:disabled {
            background: #ccc;
            color: #666;
            cursor: not-allowed;
        }

        .data-privacy-checkbox-container {
            padding: 0;
        }

        .data-privacy-checkbox-container label {
            user-select: none;
        }

        .data-privacy-checkbox-container a:hover {
            color: #ffd9c7 !important;
        }

        .form-btn:disabled {
            background: #ccc !important;
            color: #666 !important;
            cursor: not-allowed !important;
            opacity: 0.6 !important;
            transform: none !important;
            box-shadow: none !important;
        }

        .form-btn:disabled:hover {
            background: #ccc !important;
            color: #666 !important;
            transform: none !important;
            box-shadow: none !important;
        }

        @keyframes slideDownFromTop {
            0% {
                opacity: 0;
                transform: translateY(-100px);
            }
            100% {
                opacity: 1;
                transform: translateY(-50%);
            }
        }

        @media (max-width: 768px) {
            #dataPrivacyModalContent {
                width: 95%;
                max-width: 95%;
                margin: 20px auto;
                max-height: 90vh;
            }

            #dataPrivacyModal .modal-header h2 {
                font-size: 1.1rem;
            }

            #dataPrivacyModal .office-logo {
                width: 45px;
                height: 45px;
            }

            #dataPrivacyModal .office-title {
                font-size: 1rem;
            }

            #dataPrivacyModal .section h4 {
                font-size: 0.85rem;
            }

            #dataPrivacyModal .section p,
            #dataPrivacyModal .section ul {
                font-size: 0.75rem;
            }
        }

        @media (max-width: 480px) {
            #dataPrivacyModalContent {
                width: 100%;
                max-width: 100%;
                margin: 0;
                max-height: 100vh;
                border-radius: 0;
            }

            #dataPrivacyModal .modal-header {
                padding: 16px;
            }

            #dataPrivacyModal .modal-body {
                padding: 0;
            }

            #dataPrivacyModal .modal-content-inner {
                padding: 16px;
            }
        }
    </style>
</head>
<body>
    <!-- Terms and Conditions Modal -->
    <div class="modal-overlay" id="termsModal" style="display: none;">
        <div class="modal-alert terms-modal">
            <div class="modal-header">
                <h2 class="modal-title"><i class="fas fa-file-contract"></i> Terms & Conditions</h2>
                <p class="modal-subtitle">Client Portal Use Agreement</p>
            </div>
            <div class="modal-body">
                <div class="terms-scroll">
                    <div class="terms-intro">
                        <p>Welcome to the Opiña Law Office client portal. To keep your experience secure and professional, please review these plain-language guidelines.</p>
                    </div>
                    <ul class="terms-list">
                        <li>
                            <h4>1. True Information</h4>
                            <p>All details you submit must be complete and factual. Update your profile whenever something changes.</p>
                        </li>
                        <li>
                            <h4>2. Confidential Access</h4>
                            <p>Keep your login private. You’re responsible for every action taken while signed in.</p>
                        </li>
                        <li>
                            <h4>3. Respectful Use</h4>
                            <p>Only use the portal for legitimate coordination with our office. Abuse or tampering leads to revoked access.</p>
                        </li>
                        <li>
                            <h4>4. Electronic Notices</h4>
                            <p>You agree to receive reminders, updates, and notices through the contact details you provide.</p>
                        </li>
                        <li>
                            <h4>5. Consent</h4>
                            <p>Continuing past this screen confirms that you understand and accept these conditions.</p>
                        </li>
                    </ul>
                    <div class="terms-checkbox">
                        <input type="checkbox" id="termsCheckbox">
                        <label for="termsCheckbox">I have read and agree to the Terms & Conditions.</label>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button id="termsAcceptButton" class="accept-button" onclick="acceptTerms()" disabled>
                    <i class="fas fa-check"></i> Accept
                </button>
            </div>
        </div>
    </div>

    <!-- Data Privacy Waiver Modal -->
    <div id="dataPrivacyModal">
        <div id="dataPrivacyModalContent">
            <div class="modal-header">
                <h2>
                    <i class="fas fa-shield-alt"></i> Data Privacy Notice
                </h2>
            </div>
            <div class="modal-body">
                <div class="modal-content-inner">
                    <div class="office-header">
                        <div class="office-logo">
                            <img src="images/logo.jpg" alt="Opiña Law Office Logo" style="width: 100%; height: 100%; object-fit: contain; border-radius: 50%;">
                        </div>
                        <h3 class="office-title">OPIÑA LAW OFFICE</h3>
                        <p class="office-subtitle">Data Privacy Notice & Consent</p>
                    </div>

                    <div class="important-notice">
                        <h4>
                            <i class="fas fa-exclamation-triangle"></i> IMPORTANT NOTICE
                        </h4>
                        <p>
                            By accessing this system, you acknowledge that you have read, understood, and agree to the terms outlined in this Data Privacy Notice.
                        </p>
                    </div>

                    <div class="section">
                        <h4>I. Collection of Personal Information</h4>
                        <p>
                            We collect personal information necessary for providing legal services:
                        </p>
                        <ul>
                            <li>Personal identification details</li>
                            <li>Legal case information and documents</li>
                            <li>Communication records and messages</li>
                            <li>Schedule and appointment information</li>
                            <li>Government-issued identification documents</li>
                        </ul>
                    </div>

                    <div class="section">
                        <h4>II. Purpose of Data Processing</h4>
                        <p>
                            Your personal information is processed for:
                        </p>
                        <ul>
                            <li>Providing legal consultation and representation</li>
                            <li>Managing your legal cases and documents</li>
                            <li>Communicating case updates and appointments</li>
                            <li>Complying with legal and regulatory requirements</li>
                            <li>Maintaining attorney-client privilege</li>
                        </ul>
                    </div>

                    <div class="section">
                        <h4>III. Data Security & Confidentiality</h4>
                        <p>
                            We implement appropriate security measures to protect your personal information against unauthorized access, alteration, disclosure, or destruction. All data is handled with strict confidentiality in accordance with attorney-client privilege.
                        </p>
                    </div>

                    <div class="section">
                        <h4>IV. Your Rights</h4>
                        <p>
                            Under the Data Privacy Act of 2012, you have the right to:
                        </p>
                        <ul>
                            <li>Access and request copies of your personal information</li>
                            <li>Correct or update inaccurate information</li>
                            <li>Withdraw consent (subject to legal obligations)</li>
                            <li>File complaints with the National Privacy Commission</li>
                        </ul>
                    </div>

                    <div class="consent-section">
                        <h4>
                            <i class="fas fa-exclamation-triangle"></i> CONSENT DECLARATION
                        </h4>
                        <p>
                            I acknowledge that I have read and understood this Data Privacy Notice and consent to the collection, processing, and use of my personal information as described herein.
                        </p>
                        <div class="checkbox-container">
                            <input type="checkbox" id="consentCheckbox">
                            <label for="consentCheckbox">
                                I agree to the terms and conditions
                            </label>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button id="acceptButton" class="accept-button" onclick="acceptDataPrivacy()" disabled>
                    <i class="fas fa-check"></i> Accept
                </button>
            </div>
        </div>
    </div>

    <?php if (isset($_SESSION['error'])): ?>
        <div class="modal-overlay" id="errorModal">
            <div class="modal-alert">
                <div class="modal-header">
                    <h2 class="modal-title">Opiña Law Office</h2>
                    <p class="modal-subtitle">Registration Notice</p>
                </div>
                <div class="modal-body">
                    <p class="modal-message"><?php echo $_SESSION['error']; ?></p>
                    <?php if (strpos($_SESSION['error'], 'User already exists') !== false): ?>
                        <p class="modal-subtext">Please log in to continue.</p>
                    <?php elseif (strpos($_SESSION['error'], 'Phone number must be exactly 11 digits') !== false): ?>
                        <p class="modal-subtext">Please enter a valid 11-digit phone number.</p>
                    <?php elseif (strpos($_SESSION['error'], 'Please enter a valid email address') !== false): ?>
                        <p class="modal-subtext">Please check your email format and try again.</p>
                    <?php elseif (strpos($_SESSION['error'], 'Email cannot contain spaces') !== false): ?>
                        <p class="modal-subtext">Please remove any spaces from your email address.</p>
                    <?php elseif (strpos($_SESSION['error'], 'Password must be at least 8 characters') !== false): ?>
                        <p class="modal-subtext">Please ensure your password meets all requirements.</p>
                    <?php elseif (strpos($_SESSION['error'], 'Password cannot contain spaces') !== false): ?>
                        <p class="modal-subtext">Please remove any spaces from your password.</p>
                    <?php elseif (strpos($_SESSION['error'], 'Passwords do not match') !== false): ?>
                        <p class="modal-subtext">Please ensure both passwords are identical.</p>
                    <?php elseif (strpos($_SESSION['error'], 'We could not send the OTP') !== false): ?>
                        <p class="modal-subtext">Please check your email address or try again later.</p>
                    <?php else: ?>
                        <p class="modal-subtext">Please check your information and try again.</p>
                    <?php endif; ?>
                    <button class="modal-button" onclick="closeModal()">OK</button>
                </div>
            </div>
        </div>
        <?php unset($_SESSION['error']); ?>
    <?php endif; ?>

    <div class="left-container">
        <div class="title-container">
            <img src="images/logo.jpg" alt="Logo">
            <div class="title">LawOffice</div>
        </div>

        <div class="header-container">
            <h1 class="law-office-title">Opiña Law<br>Office</h1>
            <img src="images/justice.png" alt="Attorney Icon">
        </div>

        <div class="form-container">
            <h2 class="form-header">Register</h2>

            <form action="" method="post">
                <label for="lastname">Name</label>
                <div style="display: flex; gap: 8px;">
                    <input type="text" name="lastname" id="lastname" required placeholder="Lastname" style="flex:1;">
                    <input type="text" name="firstname" id="firstname" required placeholder="Firstname" style="flex:1;">
                    <input type="text" name="middlename" id="middlename" placeholder="Middlename" style="flex:1;">
                </div>

                <label for="email">Email</label>
                <input type="email" name="email" id="email" required placeholder="Enter your email" title="Please enter a valid email address">

                <label for="phone">Phone Number</label>
                <input type="text" name="phone" id="phone" required placeholder="Enter your phone number" maxlength="11" pattern="\d{11}" title="Phone number must be exactly 11 digits">

                <input type="hidden" name="user_type" value="client">

                <label for="password">Password</label>
                <div class="password-container">
                    <input type="password" name="password" id="password" required placeholder="Enter your password" oninput="this.value = this.value.replace(/\s/g, '')">
                    <i class="fas fa-eye" id="togglePassword"></i>
                </div>
                <ul style="color:#fff; font-size:12px; margin-bottom:8px; margin-top:2px; padding-left:18px;">
                    <li>Password requirements:</li>
                    <li>At least 8 characters</li>
                    <li>Must include uppercase and lowercase letters</li>
                    <li>Must include at least one number</li>
                    <li>Must include at least one special character</li>
                    <li>Allowed: ! @ # $ % ^ & * ( ) _ + - = { } [ ] : ; " ' < > , . ? / ~ ` | \</li>
                </ul>

                <label for="cpassword">Confirm Password</label>
                <div class="password-container">
                    <input type="password" name="cpassword" id="cpassword" required placeholder="Confirm your password" oninput="this.value = this.value.replace(/\s/g, '')">
                    <i class="fas fa-eye" id="toggleCPassword"></i>
                </div>

                <div class="data-privacy-checkbox-container" style="margin-top: 2px; margin-bottom: 0;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; color: #ffffff; font-size: 12px; font-weight: 400;">
                        <input type="checkbox" id="dataPrivacyCheckbox" style="width: 16px; height: 16px; accent-color: #5D0E26; cursor: pointer;">
                        <span>I agree to the <a href="#" onclick="event.preventDefault(); showDataPrivacyModal();" style="color: #ffffff; text-decoration: underline; font-weight: 500;">Data Privacy Notice</a></span>
                    </label>
                </div>

                <input type="submit" name="submit" value="Register" class="form-btn" id="registerButton" disabled>
            </form>
        </div>
    </div>

    <div class="right-container">
        <a href="index.php" class="back-button">
            <i class="fas fa-arrow-left"></i>
            Back to Home
        </a>
        <div class="login-box">
            <h1 class="mirror-shine">Already have an account?</h1>
        </div>
        <a href="login_form.php" class="login-btn">Login Now</a>
    </div>

    <script>
        let pendingFormSubmission = null;
        const TERMS_FLAG = 'termsAcceptedRegister';
        const REGISTER_SUBMITTING_FLAG = 'registerFormSubmitting';

        // Terms & Conditions Modal Functions
        function showTermsModal() {
            const modal = document.getElementById('termsModal');
            if (modal) {
                modal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
            }
        }

        function closeTermsModal() {
            const modal = document.getElementById('termsModal');
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        }

        function toggleTermsAcceptButton() {
            const checkbox = document.getElementById('termsCheckbox');
            const acceptButton = document.getElementById('termsAcceptButton');
            if (checkbox && acceptButton) {
                const enabled = checkbox.checked;
                acceptButton.disabled = !enabled;
                acceptButton.style.background = enabled ? '#5D0E26' : '#ccc';
                acceptButton.style.color = enabled ? '#fff' : '#666';
                acceptButton.style.cursor = enabled ? 'pointer' : 'not-allowed';
            }
        }

        function acceptTerms() {
            const checkbox = document.getElementById('termsCheckbox');
            if (!checkbox || !checkbox.checked) {
                alert('Please agree to the Terms & Conditions to continue.');
                return;
            }
            sessionStorage.setItem(TERMS_FLAG, 'true');
            closeTermsModal();
        }

        // Data Privacy Waiver Modal Functions
        function showDataPrivacyModal() {
            const modal = document.getElementById('dataPrivacyModal');
            const modalContent = document.getElementById('dataPrivacyModalContent');
            
            if (modal && modalContent) {
                modal.style.display = 'block';
                
                // Reset animation
                modalContent.style.animation = 'none';
                modalContent.offsetHeight; // Trigger reflow
                modalContent.style.animation = 'slideDownFromTop 0.5s ease-out';
                
                // Prevent body scroll when modal is open
                document.body.style.overflow = 'hidden';
                
                // Reset consent checkbox in modal when opening
                const consentCheckbox = document.getElementById('consentCheckbox');
                if (consentCheckbox) {
                    consentCheckbox.checked = false;
                    toggleAcceptButton();
                }
            }
        }

        function closeDataPrivacyModal() {
            const modal = document.getElementById('dataPrivacyModal');
            if (modal) {
                modal.style.display = 'none';
                // Restore body scroll
                document.body.style.overflow = 'auto';
            }
        }

        function acceptDataPrivacy() {
            const checkbox = document.getElementById('consentCheckbox');
            if (!checkbox.checked) {
                alert('Please check the consent checkbox to proceed.');
                return;
            }
            
            // Close the modal
            closeDataPrivacyModal();

            // Mark the data privacy checkbox as checked (always check it when waiver is accepted)
            const dataPrivacyCheckbox = document.getElementById('dataPrivacyCheckbox');
            if (dataPrivacyCheckbox) {
                dataPrivacyCheckbox.checked = true;
                toggleRegisterButton();
            }

            // If there's a pending form submission (from old flow), handle it
            if (pendingFormSubmission) {
                pendingFormSubmission.dataset.waiverConfirmed = 'true';
                const submitButton = pendingFormSubmission.querySelector('button[type="submit"], input[type="submit"][name="submit"]');
                sessionStorage.setItem(REGISTER_SUBMITTING_FLAG, 'true');

                if (typeof pendingFormSubmission.requestSubmit === 'function') {
                    pendingFormSubmission.requestSubmit(submitButton || undefined);
                } else {
                    // ensure PHP receives the submit field in browsers without requestSubmit
                    let tempSubmitInput = null;
                    if (!submitButton) {
                        tempSubmitInput = document.createElement('input');
                        tempSubmitInput.type = 'hidden';
                        tempSubmitInput.name = 'submit';
                        tempSubmitInput.value = 'Register';
                        pendingFormSubmission.appendChild(tempSubmitInput);
                    }
                    pendingFormSubmission.submit();
                    if (tempSubmitInput) {
                        pendingFormSubmission.removeChild(tempSubmitInput);
                    }
                }
                pendingFormSubmission = null;
            }
        }

        // Handle checkbox change to enable/disable accept button
        function toggleAcceptButton() {
            const checkbox = document.getElementById('consentCheckbox');
            const acceptButton = document.getElementById('acceptButton');
            
            if (checkbox && acceptButton) {
                if (checkbox.checked) {
                    acceptButton.style.background = '#5D0E26';
                    acceptButton.style.color = 'white';
                    acceptButton.style.cursor = 'pointer';
                    acceptButton.disabled = false;
                } else {
                    acceptButton.style.background = '#ccc';
                    acceptButton.style.color = '#666';
                    acceptButton.style.cursor = 'not-allowed';
                    acceptButton.disabled = true;
                }
            }
        }

        // Handle data privacy checkbox change to enable/disable register button
        function toggleRegisterButton() {
            const dataPrivacyCheckbox = document.getElementById('dataPrivacyCheckbox');
            const registerButton = document.getElementById('registerButton');
            
            if (dataPrivacyCheckbox && registerButton) {
                if (dataPrivacyCheckbox.checked) {
                    registerButton.disabled = false;
                } else {
                    registerButton.disabled = true;
                }
            }
        }


        // Initialize modals and bind form submission flow
        document.addEventListener('DOMContentLoaded', function() {
            sessionStorage.removeItem(REGISTER_SUBMITTING_FLAG);
            // Show Terms and Conditions modal only if not in OTP verification stage
            const hasOtpModal = <?php echo (isset($_SESSION['show_otp_modal']) && isset($_SESSION['pending_registration'])) ? 'true' : 'false'; ?>;
            if (!hasOtpModal) {
                showTermsModal();
            }

            const termsCheckbox = document.getElementById('termsCheckbox');
            if (termsCheckbox) {
                termsCheckbox.addEventListener('change', toggleTermsAcceptButton);
            }

            const waiverCheckbox = document.getElementById('consentCheckbox');
            if (waiverCheckbox) {
                waiverCheckbox.addEventListener('change', toggleAcceptButton);
            }

            // Handle data privacy checkbox click - show modal when clicked
            const dataPrivacyCheckbox = document.getElementById('dataPrivacyCheckbox');
            if (dataPrivacyCheckbox) {
                dataPrivacyCheckbox.addEventListener('click', function(e) {
                    // Prevent default checkbox behavior - we'll handle it manually
                    e.preventDefault();
                    
                    // If already checked, uncheck it and disable register
                    if (this.checked) {
                        this.checked = false;
                        toggleRegisterButton();
                    } else {
                        // Show modal first - checkbox will be checked when modal is accepted
                        showDataPrivacyModal();
                    }
                });
                
                // Initialize register button state
                toggleRegisterButton();
            }

            const form = document.querySelector('form');
            if (form) {
                form.addEventListener('submit', function(e) {
                    // Check if data privacy checkbox is checked
                    const dataPrivacyCheckbox = document.getElementById('dataPrivacyCheckbox');
                    if (!dataPrivacyCheckbox || !dataPrivacyCheckbox.checked) {
                        e.preventDefault();
                        alert('Please agree to the Data Privacy Notice to continue.');
                        return false;
                    }
                    
                    // If waiver was already confirmed (old flow), allow submission
                    if (this.dataset.waiverConfirmed === 'true') {
                        this.dataset.waiverConfirmed = 'false';
                        return;
                    }
                    
                    // Allow form submission if checkbox is checked
                    // No need to show modal anymore - it's shown when checkbox is clicked
                });
            }
        });

        // Close modal when clicking outside (disabled - user must accept)
        window.addEventListener('click', function(event) {
            const modal = document.getElementById('dataPrivacyModal');
            if (event.target === modal) {
                // Don't allow closing by clicking outside - user must explicitly accept
                // closeDataPrivacyModal();
            }
        });

        document.getElementById('togglePassword').addEventListener('click', function () {
            let passwordField = document.getElementById('password');
            let icon = this;
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });

        document.getElementById('toggleCPassword').addEventListener('click', function () {
            let passwordField = document.getElementById('cpassword');
            let icon = this;
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });

        function closeModal() {
            const modals = document.querySelectorAll('.modal-overlay');
            modals.forEach(modal => {
                modal.style.display = 'none';
            });
        }

        // Legacy function for backward compatibility
        function closePopup() {
            closeModal();
        }

        // Function to show validation modal for client-side errors
        function showValidationModal(title, message, subtext) {
            // Remove any existing validation modal
            const existingModal = document.getElementById('validationModal');
            if (existingModal) {
                existingModal.remove();
            }

            // Create modal HTML
            const modalHTML = `
                <div class="modal-overlay" id="validationModal">
                    <div class="modal-alert">
                        <div class="modal-header">
                            <h2 class="modal-title">Opiña Law Office</h2>
                            <p class="modal-subtitle">${title}</p>
                        </div>
                        <div class="modal-body">
                            <p class="modal-message">${message}</p>
                            <p class="modal-subtext">${subtext}</p>
                            <button class="modal-button" onclick="closeModal()">OK</button>
                        </div>
                    </div>
                </div>
            `;

            // Add modal to body
            document.body.insertAdjacentHTML('beforeend', modalHTML);
        }

        // Prevent spaces in critical fields (email, password, confirm password)
        ['email','password','cpassword'].forEach(function(id){
            var el = document.getElementById(id);
            if (!el) return;
            el.addEventListener('keydown', function(e){ if (e.key === ' ') e.preventDefault(); });
            el.addEventListener('input', function(){ this.value = this.value.replace(/\s+/g,''); });
        });

        // Email validation removed - now accepts all valid email addresses

        // Password validation (client-side) with specific error messages
        document.querySelector('form').addEventListener('submit', function(e) {
            var pass = document.getElementById('password').value;
            var cpass = document.getElementById('cpassword').value;
            
            // Check each password requirement individually
            var errors = [];
            
            if (pass.length < 8) {
                errors.push('• Password must be at least 8 characters long');
            }
            if (!/[a-z]/.test(pass)) {
                errors.push('• Must include at least one lowercase letter (a-z)');
            }
            if (!/[A-Z]/.test(pass)) {
                errors.push('• Must include at least one uppercase letter (A-Z)');
            }
            if (!/\d/.test(pass)) {
                errors.push('• Must include at least one number (0-9)');
            }
            if (!/[!@#$%\^&*()_\-+={}\[\]:;"'<>,.?\/~`|\\]/.test(pass)) {
                errors.push('• Must include at least one special character (! @ # $ % ^ & * etc.)');
            }
            
            if (errors.length > 0) {
                var errorMessage = errors.join('<br>');
                var exampleText = '<br><br><strong>Example of valid password:</strong><br>MyPass123!';
                showValidationModal('Password Requirements Not Met', errorMessage, exampleText);
                e.preventDefault();
                return false;
            }
            
            if (pass !== cpass) {
                showValidationModal('Password Mismatch', 'Confirm password does not match the password.', 'Please ensure both passwords are identical.');
                e.preventDefault();
                return false;
            }
        });

        // Limit phone input to 11 digits only (client-side)
        document.getElementById('phone').addEventListener('input', function(e) {
            this.value = this.value.replace(/[^\d]/g, '').slice(0, 11);
        });
    </script>

    <script src="https://kit.fontawesome.com/cc86d7b31d.js" crossorigin="anonymous"></script>

    <!-- OTP Verification Modal -->
    <?php if (isset($_SESSION['show_otp_modal']) && isset($_SESSION['pending_registration'])): ?>
    <div class="otp-modal" id="otpModal" style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(93, 14, 38, 0.8); display: flex; align-items: center; justify-content: center; z-index: 9999;">
        <div style="background: #fff; border-radius: 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3); padding: 40px 35px; max-width: 480px; width: 90%; position: relative; animation: slideIn 0.3s ease;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="color: #5D0E26; margin-bottom: 15px; font-size: 32px; font-weight: 700; font-family: 'Playfair Display', serif; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">Opiña Law Office</h2>
                <h3 style="color: #5D0E26; margin-bottom: 20px; font-size: 22px; font-weight: 600;">Verify Your Email</h3>
            </div>
            <div style="color: #666; margin-bottom: 25px; text-align: center; font-size: 15px; line-height: 1.5;">
                Enter the 6-digit OTP sent to<br><strong style="color: #5D0E26;"><?= htmlspecialchars($_SESSION['pending_registration']['email']) ?></strong>
            </div>
            
            <form method="post" style="margin-bottom: 20px;" id="otpForm" onsubmit="return false;">
                <div style="margin-bottom: 25px;">
                    <input type="text" name="otp" maxlength="6" pattern="\d{6}" placeholder="Enter 6-digit OTP" required 
                           style="width: 100%; padding: 15px; font-size: 18px; border: 2px solid #e0e0e0; border-radius: 8px; outline: none; transition: all 0.3s ease; text-align: center; letter-spacing: 3px; font-weight: 600; background: #f9f9f9;"
                           onfocus="this.style.borderColor='#5D0E26'; this.style.background='#fff';"
                           onblur="this.style.borderColor='#e0e0e0'; this.style.background='#f9f9f9';">
                </div>
                <button type="button" onclick="verifyOTP()" 
                        style="width: 100%; background: linear-gradient(135deg, #5D0E26, #8B1538); color: #fff; border: none; padding: 16px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(93, 14, 38, 0.4);"
                        onmouseover="this.style.background='linear-gradient(135deg, #8B1538, #5D0E26)'; this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 20px rgba(93, 14, 38, 0.5)';"
                        onmouseout="this.style.background='linear-gradient(135deg, #5D0E26, #8B1538)'; this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px rgba(93, 14, 38, 0.4)';">
                    Verify OTP
                </button>
            </form>
            
            <?php if (isset($_SESSION['error'])): ?>
            <div style="color: #e74c3c; margin-bottom: 15px; text-align: center; font-size: 13px; background: #ffe6e6; padding: 10px; border-radius: 6px; border-left: 4px solid #e74c3c;">
                <?= htmlspecialchars($_SESSION['error']) ?>
            </div>
            <?php unset($_SESSION['error']); ?>
            <?php endif; ?>
            
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="closeOtpModal()" style="background: none; border: none; color: #5D0E26; text-decoration: none; font-size: 14px; font-weight: 500; cursor: pointer; padding: 8px 15px; border-radius: 6px; transition: all 0.3s ease; margin-right: 15px;" onmouseover="this.style.background='#f0f0f0'; this.style.color='#8B1538';" onmouseout="this.style.background='transparent'; this.style.color='#5D0E26';">
                    ← Cancel & Start Over
                </button>
                <button onclick="resendOTP()" style="background: none; border: none; color: #5D0E26; text-decoration: none; font-size: 14px; font-weight: 500; cursor: pointer; padding: 8px 15px; border-radius: 6px; transition: all 0.3s ease; margin-right: 15px;" onmouseover="this.style.background='#f0f0f0'; this.style.color='#8B1538';" onmouseout="this.style.background='transparent'; this.style.color='#5D0E26';">
                    ↻ Resend OTP
                </button>
            </div>
        </div>
    </div>

    <script>
        
        function closeOtpModal() {
            // Close the modal immediately
            const modal = document.getElementById('otpModal');
            if (modal) {
                modal.style.display = 'none';
            }
            
            // Clear the OTP timer
            if (window.__otpTimerInterval) {
                clearInterval(window.__otpTimerInterval);
                window.__otpTimerInterval = null;
            }
            
            // Clear the OTP session data via AJAX
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                credentials: 'same-origin',
                body: 'cancel_otp=1'
            }).then(function(res) {
                return res.text();
            }).then(function(txt) {
                // Clear form fields for fresh registration
                clearRegistrationForm();
                
                // Show a message that they can register again
                if (typeof showMessage === 'function') {
                    showMessage('OTP verification canceled. You can now register again.', 'info');
                } else {
                    // Fallback if showMessage function doesn't exist
                    showValidationModal('OTP Verification Canceled', 'OTP verification canceled. You can now register again.', 'You can now fill out the registration form again.');
                }
            }).catch(function(error) {
                console.error('Error:', error);
            });
        }

        function clearRegistrationForm() {
            // Clear all form inputs
            const form = document.querySelector('form');
            if (form) {
                const inputs = form.querySelectorAll('input[type="text"], input[type="email"], input[type="password"]');
                inputs.forEach(input => {
                    input.value = '';
                });
                
                // Focus on the first input field
                const firstInput = form.querySelector('input[type="text"]');
                if (firstInput) {
                    firstInput.focus();
                }
            }
        }

        // Function to resend OTP (consolidated version)
        // Global flags to prevent race conditions between resend and verify
        window.__resending = window.__resending || false;
        window.__verifying = window.__verifying || false;

        function resendOTP() {
            if (window.__verifying) {
                showMessage('Verification in progress. Please wait for it to finish or try again in a moment.', 'info');
                return;
            }
            if (window.__resending) return;
            const resendBtn = document.querySelector('button[onclick="resendOTP()"]');
            const originalText = resendBtn.textContent;
            resendBtn.textContent = 'Sending...';
            resendBtn.disabled = true;
            window.__resending = true;
            
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                credentials: 'same-origin',
                body: 'resend_otp=1'
            }).then(function(res) {
                return res.text();
            }).then(function(response) {
                if (response === 'OK') {
                    showMessage('New OTP sent successfully!', 'success');
                    // Clear the OTP input
                    const otpInput = document.querySelector('input[name="otp"]');
                    if (otpInput) {
                        otpInput.value = '';
                        // Add delay to prevent focus conflicts
                        setTimeout(function() {
                            otpInput.focus();
                        }, 50);
                    }
                    // Reset and restart 15-minute countdown
                    try {
                        const timerSpan = document.getElementById('otpTimer');
                        if (timerSpan && timerSpan.parentElement) {
                            timerSpan.parentElement.remove();
                        }
                    } catch (e) {}
                    if (window.__otpTimerInterval) {
                        clearInterval(window.__otpTimerInterval);
                        window.__otpTimerInterval = null;
                    }
                    startOTPCountdown();
                } else {
                    showMessage('Failed to send new OTP. Please try again.', 'error');
                }
            }).catch(function(error) {
                console.error('Error:', error);
                showMessage('Failed to send new OTP. Please try again.', 'error');
            }).finally(function() {
                // Reset button state
                resendBtn.textContent = originalText;
                resendBtn.disabled = false;
                window.__resending = false;
            });
        }
        

        // Auto-focus on OTP input when modal appears
        document.addEventListener('DOMContentLoaded', function() {
            const otpInput = document.querySelector('input[name="otp"]');
            const otpModal = document.getElementById('otpModal');
            
            // Only start timer if OTP modal exists and is visible
            if (otpInput && otpModal) {
                // Add small delay to prevent focus conflicts
                setTimeout(function() {
                    otpInput.focus();
                    // Clear any previous OTP input
                    otpInput.value = '';
                }, 100);
                
                // Start OTP expiration countdown
                startOTPCountdown();
            }
        });
        
        function startOTPCountdown() {
            // OTP expires in 1 minute (60 seconds)
            let timeLeft = 60;
            const countdownElement = document.createElement('div');
            countdownElement.style.cssText = 'text-align: center; color: #e74c3c; font-size: 12px; margin-top: 10px; font-weight: 500;';
            countdownElement.innerHTML = `⏰ OTP expires in <span id="otpTimer">1:00</span>`;
            
            // Insert countdown after the OTP input
            const otpInput = document.querySelector('input[name="otp"]');
            if (otpInput && otpInput.parentNode) {
                otpInput.parentNode.appendChild(countdownElement);
            }
            
            // Keep reference globally to clear when resending
            if (window.__otpTimerInterval) {
                clearInterval(window.__otpTimerInterval);
            }
            const timer = setInterval(() => {
                timeLeft--;
                const minutes = Math.floor(timeLeft / 60);
                const seconds = timeLeft % 60;
                const timerSpan = document.getElementById('otpTimer');
                if (timerSpan) {
                    timerSpan.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                }
                
                if (timeLeft <= 0) {
                    clearInterval(timer);
                    window.__otpTimerInterval = null;
                    
                    // Only show expiration message if OTP modal is actually visible
                    const otpModal = document.getElementById('otpModal');
                    if (otpModal && otpModal.style.display !== 'none') {
                        showMessage('OTP has expired. Click Resend OTP to get a new code.', 'error');
                    }
                    // Keep the modal open so the user can press Resend OTP
                }
            }, 1000);
            window.__otpTimerInterval = timer;
        }
        
        function verifyOTP() {
            if (window.__resending) {
                showMessage('Please wait, a new OTP is being sent. Try again in a moment.', 'info');
                return;
            }
            
            const otpInput = document.querySelector('input[name="otp"]');
            const otp = otpInput.value.trim();
            
            if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
                showMessage('Please enter a valid 6-digit OTP', 'error');
                setTimeout(function() {
                    otpInput.focus();
                }, 50);
                return;
            }
            
            // Show loading state
            const verifyBtn = document.querySelector('button[onclick="verifyOTP()"]');
            const originalText = verifyBtn.textContent;
            verifyBtn.textContent = 'Verifying...';
            verifyBtn.disabled = true;
            verifyBtn.style.opacity = '0.7';
            window.__verifying = true;
            
            // Clear any previous error messages
            const existingError = document.querySelector('.message-popup.error');
            if (existingError) {
                existingError.remove();
            }
            
            // Submit OTP for verification
            const requestBody = 'verify_otp=1&otp=' + encodeURIComponent(otp);
            
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                credentials: 'same-origin',
                body: requestBody
            }).then(function(res) {
                return res.text();
            }).then(function(response) {
                try {
                    // Try to parse as JSON
                    const data = JSON.parse(response);
                    
                    if (data.status === 'success') {
                        // Clear the OTP timer
                        if (window.__otpTimerInterval) {
                            clearInterval(window.__otpTimerInterval);
                            window.__otpTimerInterval = null;
                        }
                        
                        // Success - close the modal and redirect immediately
                        const modal = document.getElementById('otpModal');
                        if (modal) {
                            modal.style.display = 'none';
                        }
                        
                        // Redirect immediately (server will show success message on login page)
                        window.location.href = data.redirect;
                    } else if (data.status === 'error') {
                        // Error - show error message
                        showMessage(data.message, 'error');
                        
                        if (data.message.includes('Invalid OTP')) {
                            otpInput.value = '';
                            setTimeout(function() {
                                otpInput.focus();
                            }, 50);
                        }
                    } else {
                        // Unknown status
                        showMessage('Verification failed. Please try again.', 'error');
                        setTimeout(function() {
                            otpInput.focus();
                        }, 50);
                    }
                } catch (e) {
                    // Not JSON - fallback to old text-based parsing
                    if (response.includes('login_form.php')) {
                        // Clear the OTP timer
                        if (window.__otpTimerInterval) {
                            clearInterval(window.__otpTimerInterval);
                            window.__otpTimerInterval = null;
                        }
                        
                        // Success - close modal and redirect immediately
                        const modal = document.getElementById('otpModal');
                        if (modal) {
                            modal.style.display = 'none';
                        }
                        // Redirect immediately (server will show success message on login page)
                        window.location.href = 'login_form.php';
                    } else if (response.includes('OTP expired')) {
                        // OTP expired
                        showMessage('OTP has expired. Click Resend OTP to get a new code.', 'error');
                        // Keep modal open so user can press Resend OTP
                    } else if (response.includes('Invalid OTP')) {
                        // Invalid OTP
                        showMessage('Invalid OTP. Please check and try again.', 'error');
                        otpInput.value = '';
                        setTimeout(function() {
                            otpInput.focus();
                        }, 50);
                    } else {
                        // Unknown response - show generic error
                        showMessage('Verification failed. Please try again.', 'error');
                        setTimeout(function() {
                            otpInput.focus();
                        }, 50);
                    }
                }
            }).catch(function(error) {
                showMessage('Verification failed. Please try again.', 'error');
            }).finally(function() {
                // Reset button state
                verifyBtn.textContent = originalText;
                verifyBtn.disabled = false;
                verifyBtn.style.opacity = '1';
                window.__verifying = false;
            });
        }

        // Add animation keyframes
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: scale(0.9) translateY(-20px);
                }
                to {
                    opacity: 1;
                    transform: scale(1) translateY(0);
                }
            }
        `;
        document.head.appendChild(style);

        // Function to show messages using professional modal system
        function showMessage(message, type = 'info') {
            // Remove any existing message modal
            const existingModal = document.getElementById('messageModal');
            if (existingModal) {
                existingModal.remove();
            }

            // Determine title and subtext based on type
            let title, subtext;
            if (type === 'success') {
                title = 'Success';
                subtext = 'You can now proceed with your login.';
            } else if (type === 'error') {
                title = 'Error';
                subtext = 'Please try again or contact support if the problem persists.';
            } else {
                title = 'Information';
                subtext = 'Please follow the instructions provided.';
            }

            // Create modal HTML
            const modalHTML = `
                <div class="modal-overlay" id="messageModal">
                    <div class="modal-alert">
                        <div class="modal-header">
                            <h2 class="modal-title">Opiña Law Office</h2>
                            <p class="modal-subtitle">${title}</p>
                        </div>
                        <div class="modal-body">
                            <p class="modal-message">${message}</p>
                            <p class="modal-subtext">${subtext}</p>
                            <button class="modal-button" onclick="closeModal()">OK</button>
                        </div>
                    </div>
                </div>
            `;

            // Add modal to body
            document.body.insertAdjacentHTML('beforeend', modalHTML);
        }
        
        
        
    </script>
    <?php endif; ?>
    
    <script>
        // Prevent back button access to register form when already logged in
        window.addEventListener('pageshow', function(event) {
            if (event.persisted) {
                // Page was loaded from cache, check if user is logged in
                fetch('check_session.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        action: 'check_login_status'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.logged_in) {
                        // User is logged in, redirect to appropriate dashboard
                        window.location.href = data.dashboard_url;
                    }
                })
                .catch(error => {
                    console.log('Session check failed:', error);
                });
            }
        });
    </script>
</body>
</html>
