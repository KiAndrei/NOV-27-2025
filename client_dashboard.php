<?php
session_start();
if (!isset($_SESSION['client_name']) || $_SESSION['user_type'] !== 'client') {
    header('Location: login_form.php');
    exit();
}

// Set cache control headers to prevent back button access after logout
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

require_once 'config.php';
$client_id = $_SESSION['user_id'];

// Check if this is a first-time login AND account was created by attorney/admin
$stmt = $conn->prepare("SELECT profile_image, first_login, created_by FROM user_form WHERE id=?");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
$profile_image = '';
$is_first_login = false;
$show_password_modal = false;
if ($res && $row = $res->fetch_assoc()) {
    $profile_image = $row['profile_image'];
    $is_first_login = ($row['first_login'] == 1);
    // Only show password change modal if account was created by attorney/admin (not self-registered)
    $show_password_modal = $is_first_login && !is_null($row['created_by']);
}
if (!$profile_image || !file_exists($profile_image)) {
        $profile_image = 'images/default-avatar.jpg';
    }
// Total cases
$stmt = $conn->prepare("SELECT COUNT(*) FROM attorney_cases WHERE client_id=?");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$total_cases = $stmt->get_result()->fetch_row()[0];
// Total documents (from attorney_documents related to client's cases)
$stmt = $conn->prepare("SELECT COUNT(*) FROM attorney_document_activity ada 
    INNER JOIN attorney_cases ac ON ada.case_id = ac.id 
    WHERE ac.client_id = ?");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$total_documents = $stmt->get_result()->fetch_row()[0];
// Upcoming hearings (next 7 days)
$today = date('Y-m-d');
$next_week = date('Y-m-d', strtotime('+7 days'));
$stmt = $conn->prepare("SELECT COUNT(*) FROM case_schedules WHERE client_id=? AND date BETWEEN ? AND ?");
$stmt->bind_param("iss", $client_id, $today, $next_week);
$stmt->execute();
$upcoming_hearings = $stmt->get_result()->fetch_row()[0];

// Completed/Closed cases count
$completed_cases = 0;
$stmt = $conn->prepare("SELECT COUNT(*) FROM attorney_cases WHERE client_id=? AND status IN ('Completed', 'Closed')");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$completed_cases = $stmt->get_result()->fetch_row()[0];

// Case status distribution for this client
$status_counts = [];
$stmt = $conn->prepare("SELECT status, COUNT(*) as cnt FROM attorney_cases WHERE client_id=? GROUP BY status");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $status_counts[$row['status'] ?? 'Unknown'] = (int)$row['cnt'];
}

// If no cases exist, show sample data
if (empty($status_counts) || array_sum($status_counts) == 0) {
    $status_counts = [
        'Active' => 8,
        'Pending' => 5,
        'Completed' => 12
    ];
}

// Recent activities - All client activities
$recent_activities = [];

// 1. Cases assigned to client
$stmt = $conn->prepare("SELECT 'case' as type, CONCAT('Case: ', title) as title, created_at as activity_date FROM attorney_cases WHERE client_id=? ORDER BY created_at DESC LIMIT 3");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Case', 'title' => $row['title'], 'date' => $row['activity_date'], 'icon' => 'gavel'];
}

// 2. Client requests submitted
$stmt = $conn->prepare("SELECT 'request' as type, CONCAT('Request Submitted: ', request_id) as title, submitted_at as activity_date FROM client_request_form WHERE client_id=? ORDER BY submitted_at DESC LIMIT 5");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Request', 'title' => $row['title'], 'date' => $row['activity_date'], 'icon' => 'file-alt'];
}

// 3. Messages sent by client (client_messages - client is sender)
$stmt = $conn->prepare("SELECT 'message' as type, CONCAT('Message sent to attorney') as title, sent_at as activity_date FROM client_messages WHERE client_id=? ORDER BY sent_at DESC LIMIT 5");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Message', 'title' => $row['title'], 'date' => $row['activity_date'], 'icon' => 'comment'];
}

// 4. Messages sent by client (client_attorney_messages - client is sender)
$stmt = $conn->prepare("SELECT 'message' as type, CONCAT('Message sent to attorney') as title, sent_at as activity_date FROM client_attorney_messages WHERE sender_id=? AND sender_type='client' ORDER BY sent_at DESC LIMIT 5");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Message', 'title' => $row['title'], 'date' => $row['activity_date'], 'icon' => 'comment'];
}

// 5. Document generation submissions
$stmt = $conn->prepare("SELECT 'document' as type, CONCAT('Document Generated: ', document_type) as title, submitted_at as activity_date FROM client_document_generation WHERE client_id=? ORDER BY submitted_at DESC LIMIT 5");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Document', 'title' => $row['title'], 'date' => $row['activity_date'], 'icon' => 'file-pdf'];
}

// 6. Client-Employee messages
$stmt = $conn->prepare("SELECT 'message' as type, CONCAT('Message sent') as title, sent_at as activity_date FROM client_employee_messages WHERE sender_id=? AND sender_type='client' ORDER BY sent_at DESC LIMIT 5");
$stmt->bind_param("i", $client_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Message', 'title' => $row['title'], 'date' => $row['activity_date'], 'icon' => 'comment'];
}

// Sort by date (most recent first)
usort($recent_activities, function($a, $b) {
    return strtotime($b['date']) - strtotime($a['date']);
});

// Get top 10 most recent activities
$recent_activities = array_slice($recent_activities, 0, 10);

// Monthly case trends for this client
$monthly_cases = array_fill(1, 12, 0);
$year = date('Y');
$stmt = $conn->prepare("SELECT MONTH(created_at) as month, COUNT(*) as cnt FROM attorney_cases WHERE client_id=? AND YEAR(created_at) = ? GROUP BY month");
$stmt->bind_param("ii", $client_id, $year);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $monthly_cases[(int)$row['month']] = (int)$row['cnt'];
}

// If no monthly data exists, show sample data
if (array_sum($monthly_cases) == 0) {
    $monthly_cases = [2, 3, 5, 2, 6, 4, 7, 5, 3, 6, 4, 2]; // Sample data for each month
}

// Fetch recent announcements
$announcements = [];
$stmt = $conn->prepare("SELECT * FROM announcements ORDER BY created_at DESC LIMIT 2");
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $announcements[] = $row;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Client Dashboard - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?= time() ?>">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="assets/js/unread-messages.js?v=<?= time() ?>"></script>
    <style>
        .chart-container {
            position: relative;
            height: 300px;
        }

        .sample-data-overlay {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(255, 255, 255, 0.95);
            border: 2px solid #5D0E26;
            border-radius: 8px;
            padding: 10px 15px;
            font-size: 13px;
            font-weight: bold;
            color: #5D0E26;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            z-index: 1000;
            pointer-events: none;
        }

        .sample-data-overlay i {
            font-size: 11px;
        }

        /* Modern Statistics Cards */
        .stat-card-modern {
            transition: all 0.3s ease;
        }

        .stat-card-modern:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 30px rgba(93, 14, 38, 0.15) !important;
            border-color: rgba(93, 14, 38, 0.3) !important;
        }

        /* Responsive Design for Cards */
        @media (max-width: 1200px) {
            .dashboard-cards {
                grid-template-columns: repeat(2, 1fr) !important;
            }
        }

        @media (max-width: 768px) {
            .dashboard-cards {
                grid-template-columns: 1fr !important;
            }
        }

        /* Enhanced Mobile Responsive Styles */
        @media (max-width: 968px) {
            /* Announcements and Weather grid - stack on tablets */
            div[style*="grid-template-columns: 1fr calc(33.333% - 16px)"] {
                display: flex !important;
                flex-direction: column !important;
                gap: 20px !important;
            }
            
            /* Make sure announcements is first, weather is second */
            div[style*="grid-template-columns: 1fr calc(33.333% - 16px)"] > .dashboard-graph:first-child {
                order: 1;
            }
            
            div[style*="grid-template-columns: 1fr calc(33.333% - 16px)"] > .dashboard-graph:last-child {
                order: 2;
            }
        }

        @media (max-width: 768px) {
            /* Header adjustments - keep it compact */
            .header {
                flex-direction: row;
                align-items: center;
                justify-content: space-between;
                gap: 10px;
                padding: 8px 16px;
            }
            
            .header > div:first-child {
                flex: 1;
            }
            
            .header h1 {
                font-size: 1.3rem;
                margin-bottom: 2px;
            }
            
            .header .page-subtitle {
                font-size: 0.8rem;
            }
            
            .user-info {
                align-self: center;
            }
            
            .user-info img {
                width: 40px;
                height: 40px;
                margin-right: 10px;
            }
            
            .user-details {
                display: none;
            }
            
            /* Dashboard statistics cards */
            .dashboard-cards {
                grid-template-columns: 1fr !important;
                gap: 16px !important;
            }
            
            .stat-card-modern {
                padding: 20px !important;
            }
            
            .stat-card-modern > div > div:first-child {
                width: 56px !important;
                height: 56px !important;
                font-size: 1.5rem !important;
            }
            
            .stat-card-modern h3 {
                font-size: 0.85rem !important;
            }
            
            .stat-card-modern p {
                font-size: 1.75rem !important;
            }
            
            /* Announcements and weather section - stacked vertically */
            div[style*="grid-template-columns: 1fr calc(33.333% - 16px)"] {
                display: flex !important;
                flex-direction: column !important;
                gap: 20px !important;
                margin-bottom: 24px !important;
            }
            
            /* Ensure proper order: Announcements first, Weather second */
            div[style*="grid-template-columns: 1fr calc(33.333% - 16px)"] > .dashboard-graph {
                width: 100% !important;
            }
            
            .dashboard-graph {
                padding: 24px 16px !important;
            }
            
            .dashboard-graph h3 {
                font-size: 1.2rem !important;
            }
            
            /* Announcement carousel */
            .announcement-slide img {
                height: 300px !important;
            }
            
            /* Announcement description - smaller text */
            .announcement-slide > div:first-child p {
                font-size: 0.85rem !important;
                line-height: 1.5 !important;
                max-height: 90px !important;
                overflow: hidden !important;
                text-overflow: ellipsis !important;
                display: -webkit-box !important;
                -webkit-line-clamp: 4 !important;
                -webkit-box-orient: vertical !important;
            }
            
            /* Weather widget adjustments */
            .dashboard-graph > div > div:nth-child(1) {
                font-size: 2rem !important;
            }
            
            .dashboard-graph > div > div:nth-child(2) {
                font-size: 1.75rem !important;
            }
            
            /* Charts section */
            .chart-container {
                height: 250px !important;
            }
            
            /* Chart overlay text */
            .sample-data-overlay {
                font-size: 11px !important;
                padding: 8px 12px !important;
            }
            
            /* Recent activities section */
            body > div.main-content > div:nth-child(5) {
                padding: 20px !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) {
                padding: 20px !important;
                max-height: 350px !important;
            }
            
            /* Activity items */
            body > div.main-content > div:nth-child(5) > div:nth-child(2) > div {
                padding: 12px !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) > div > div:first-child {
                width: 35px !important;
                height: 35px !important;
                font-size: 0.9rem !important;
            }
            
            /* Logout Modal */
            #logoutConfirmModal > div {
                width: 95% !important;
                max-width: 95% !important;
            }
            
            #logoutConfirmModal h2 {
                font-size: 1.2rem !important;
            }
            
            #logoutConfirmModal button {
                padding: 10px 20px !important;
                font-size: 13px !important;
            }
            
            /* First Login Modal */
            #firstLoginModal > div {
                width: 95% !important;
                max-width: 95% !important;
            }
            
            #firstLoginModal h2 {
                font-size: 18px !important;
            }
            
            #firstLoginModal button {
                padding: 10px 20px !important;
                font-size: 13px !important;
            }
            
            /* Image Modal */
            #imageModal > div {
                max-width: 95% !important;
                max-height: 85% !important;
            }
        }

        @media (max-width: 480px) {
            /* Header ultra mobile - keep compact */
            .header {
                padding: 6px 12px;
            }
            
            .header h1 {
                font-size: 1.1rem !important;
            }
            
            .header .page-subtitle {
                font-size: 0.75rem !important;
            }
            
            .user-info img {
                width: 36px;
                height: 36px;
                margin-right: 8px;
            }
            
            .user-details {
                display: none;
            }
            
            /* Statistics cards ultra mobile */
            .stat-card-modern {
                padding: 16px !important;
            }
            
            .stat-card-modern > div {
                gap: 12px !important;
            }
            
            .stat-card-modern > div > div:first-child {
                width: 50px !important;
                height: 50px !important;
                font-size: 1.3rem !important;
            }
            
            .stat-card-modern h3 {
                font-size: 0.8rem !important;
            }
            
            .stat-card-modern p {
                font-size: 1.5rem !important;
            }
            
            /* Announcements and Weather - keep stacked */
            div[style*="grid-template-columns: 1fr calc(33.333% - 16px)"] {
                display: flex !important;
                flex-direction: column !important;
                gap: 16px !important;
            }
            
            /* Announcements section */
            .dashboard-graph {
                padding: 20px 12px !important;
            }
            
            .dashboard-graph h3 {
                font-size: 1.1rem !important;
                gap: 8px !important;
            }
            
            .dashboard-graph h3 i {
                font-size: 0.9rem !important;
            }
            
            .announcement-slide {
                padding: 12px !important;
            }
            
            .announcement-slide > div:first-child {
                margin-bottom: 12px !important;
            }
            
            /* Announcement description text - smaller and compact */
            .announcement-slide > div:first-child p {
                font-size: 0.75rem !important;
                line-height: 1.4 !important;
                max-height: 60px !important;
                overflow: hidden !important;
                text-overflow: ellipsis !important;
                display: -webkit-box !important;
                -webkit-line-clamp: 3 !important;
                -webkit-box-orient: vertical !important;
            }
            
            .announcement-slide > div:nth-child(2) {
                height: 250px !important;
            }
            
            .announcement-slide button {
                padding: 6px 14px !important;
                font-size: 12px !important;
            }
            
            /* Weather widget ultra mobile */
            .dashboard-graph > div > div:nth-child(1) {
                font-size: 1.8rem !important;
                margin-bottom: 12px !important;
            }
            
            .dashboard-graph > div > div:nth-child(2) {
                font-size: 1.5rem !important;
            }
            
            .dashboard-graph > div > div:nth-child(3) {
                font-size: 0.85rem !important;
            }
            
            .dashboard-graph > div > div:nth-child(4) {
                font-size: 0.8rem !important;
            }
            
            .dashboard-graph > div > div:nth-child(5) > div {
                font-size: 0.8rem !important;
                margin-bottom: 8px !important;
            }
            
            .dashboard-graph > div > div:nth-child(5) > div:last-child {
                font-size: 0.7rem !important;
                margin-top: 12px !important;
            }
            
            /* Chart section */
            body > div.main-content > div:nth-child(4) > div {
                padding: 20px 12px !important;
            }
            
            body > div.main-content > div:nth-child(4) > div > div:first-child h2 {
                font-size: 1.4rem !important;
                gap: 8px !important;
            }
            
            body > div.main-content > div:nth-child(4) > div > div:nth-child(2) {
                padding: 16px !important;
            }
            
            .chart-container {
                height: 220px !important;
            }
            
            .sample-data-overlay {
                font-size: 10px !important;
                padding: 6px 10px !important;
            }
            
            /* Recent activities ultra mobile */
            body > div.main-content > div:nth-child(5) {
                padding: 16px !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:first-child h2 {
                font-size: 1.4rem !important;
                gap: 8px !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) {
                padding: 16px !important;
                max-height: 300px !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) > div {
                padding: 10px !important;
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) > div > div:first-child {
                width: 32px !important;
                height: 32px !important;
                font-size: 0.8rem !important;
                margin-right: 0 !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) > div > div:nth-child(2) {
                margin-left: 0 !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) > div > div:nth-child(2) > div:first-child {
                font-size: 0.9rem !important;
            }
            
            body > div.main-content > div:nth-child(5) > div:nth-child(2) > div > div:nth-child(2) > div:nth-child(2) {
                font-size: 0.8rem !important;
            }
            
            /* Logout Modal ultra mobile */
            #logoutConfirmModal > div {
                width: 100% !important;
                max-width: 100% !important;
                border-radius: 0 !important;
            }
            
            #logoutConfirmModal > div > div:first-child {
                padding: 16px 20px !important;
            }
            
            #logoutConfirmModal h2 {
                font-size: 1.1rem !important;
            }
            
            #logoutConfirmModal p {
                font-size: 0.85rem !important;
            }
            
            #logoutConfirmModal > div > div:nth-child(2) {
                padding: 20px !important;
            }
            
            #logoutConfirmModal button {
                padding: 10px 18px !important;
                font-size: 12px !important;
            }
            
            /* First Login Modal ultra mobile */
            #firstLoginModal > div {
                width: 100% !important;
                max-width: 100% !important;
                border-radius: 0 !important;
            }
            
            #firstLoginModal > div > div:first-child {
                padding: 16px !important;
            }
            
            #firstLoginModal h2 {
                font-size: 16px !important;
            }
            
            #firstLoginModal p {
                font-size: 12px !important;
            }
            
            #firstLoginModal > div > div:nth-child(2) {
                padding: 20px !important;
            }
            
            #firstLoginModal > div > div:nth-child(2) > div:first-child {
                padding: 12px !important;
                margin-bottom: 16px !important;
            }
            
            #firstLoginModal > div > div:nth-child(2) > div:first-child h4 {
                font-size: 12px !important;
            }
            
            #firstLoginModal > div > div:nth-child(2) > div:first-child p {
                font-size: 11px !important;
            }
            
            #firstLoginModal > div > div:nth-child(2) > p:nth-child(2) {
                font-size: 14px !important;
            }
            
            #firstLoginModal > div > div:nth-child(2) > p:nth-child(3) {
                font-size: 12px !important;
                margin-bottom: 20px !important;
            }
            
            #firstLoginModal button {
                padding: 10px 20px !important;
                font-size: 12px !important;
                flex: 1;
            }
            
            #firstLoginModal > div > div:nth-child(2) > div:last-child {
                flex-direction: column !important;
                gap: 10px !important;
            }
            
            /* Image zoom modal ultra mobile */
            #imageModal > div {
                max-width: 100% !important;
                max-height: 90% !important;
            }
            
            #imageModal > div > img {
                border-radius: 0 !important;
            }
            
            #imageModal > div:nth-child(2) {
                top: 15px !important;
                right: 15px !important;
                font-size: 24px !important;
            }
        }

        @media (max-width: 360px) {
            /* Extra small screens */
            .header h1 {
                font-size: 1.3rem !important;
            }
            
            .stat-card-modern p {
                font-size: 1.3rem !important;
            }
            
            .dashboard-graph h3 {
                font-size: 1rem !important;
            }
            
            .chart-container {
                height: 200px !important;
            }
        }

        /* Touch device optimizations */
        @media (hover: none) and (pointer: coarse) {
            .stat-card-modern:hover {
                transform: none !important;
            }
            
            .nav-btn,
            .modal-button,
            #acceptButton,
            button {
                min-height: 44px;
                -webkit-tap-highlight-color: transparent;
            }
            
            /* Larger touch areas for announcement navigation */
            .nav-btn {
                padding: 10px 18px !important;
            }
            
            .nav-dot {
                width: 10px !important;
                height: 10px !important;
            }
        }

        /* Hamburger Menu Styles */
        .hamburger-menu {
            display: none;
            position: relative;
            z-index: 10001;
            background: var(--gradient-primary);
            border: none;
            border-radius: 8px;
            padding: 8px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);
            transition: all 0.3s ease;
            align-items: center;
            justify-content: center;
        }

        .hamburger-menu:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(93, 14, 38, 0.4);
        }

        .hamburger-menu i {
            color: white;
            font-size: 1.4rem;
            display: block;
        }

        .header .hamburger-menu {
            margin-right: 12px;
        }

        /* Sidebar overlay for mobile */
        .sidebar-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 999;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .sidebar-overlay.active {
            display: block;
            opacity: 1;
        }

        .sidebar-close {
            display: none;
            position: absolute;
            top: 12px;
            right: 12px;
            background: rgba(255, 255, 255, 0.12);
            border: none;
            border-radius: 50%;
            width: 36px;
            height: 36px;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
            color: white;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .sidebar-close:hover {
            background: rgba(255, 255, 255, 0.25);
        }

        .main-content {
            padding-top: 12px !important;
        }

        .main-content .header {
            margin-top: 0 !important;
        }

        /* Mobile sidebar adjustments */
        @media (max-width: 768px) {
            .hamburger-menu {
                display: inline-flex;
                order: -1;
                margin-right: 12px;
            }

            .sidebar {
                position: fixed;
                left: -240px;
                top: 0;
                height: 100vh;
                width: 240px !important;
                transition: left 0.3s ease;
                z-index: 10000;
                overflow-y: auto;
            }

            .sidebar.active {
                left: 0;
            }

            .sidebar-close {
                display: flex;
            }

            .sidebar-header h2,
            .sidebar-menu span,
            .sidebar-menu .text-content {
                display: block !important;
            }

            .sidebar-menu a {
                justify-content: flex-start !important;
                padding: 12px 15px !important;
            }

            .sidebar-menu i {
                margin-right: 12px !important;
            }

            /* Force main content to full width */
            body {
                display: block;
                overflow-x: hidden;
            }

            .main-content {
                margin-left: 0 !important;
                margin-right: 0 !important;
                width: 100% !important;
                max-width: 100vw !important;
                padding: 16px !important;
                padding-top: 12px !important;
                min-height: 100vh;
                box-sizing: border-box;
            }

            /* Ensure header takes full width */
            .header {
                width: 100%;
                max-width: 100%;
                box-sizing: border-box;
            }

            /* Ensure all content sections take full width */
            .dashboard-cards,
            .dashboard-graph,
            body > div.main-content > div {
                width: 100%;
                max-width: 100%;
                box-sizing: border-box;
            }
        }

        @media (max-width: 480px) {
            .hamburger-menu {
                padding: 6px;
            }

            .hamburger-menu i {
                font-size: 1.1rem;
            }

            .sidebar {
                width: 220px !important;
                left: -220px;
            }

            .main-content {
                margin-left: 0 !important;
                width: 100% !important;
                max-width: 100vw !important;
                padding: 12px !important;
                padding-top: 10px !important;
            }
            
            /* Header ultra compact */
            .header {
                padding: 6px 12px !important;
            }

            /* Override any dashboard.css settings */
            body {
                overflow-x: hidden;
            }
        }

    </style>
</head>
<body>
    <!-- Hamburger Menu Button -->
    <button class="hamburger-menu" id="hamburgerMenu" aria-label="Toggle menu">
        <i class="fas fa-bars"></i>
    </button>

    <!-- Sidebar Overlay -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>

    <div class="sidebar client-sidebar" id="sidebar">
        <button class="sidebar-close" id="sidebarCloseBtn" aria-label="Close menu">
            <i class="fas fa-times"></i>
        </button>
        <div class="sidebar-header">
            <img src="images/logo.jpg" alt="Logo">
            <h2>Opiña Law Office</h2>
        </div>
        <ul class="sidebar-menu">
            <li>
                <a href="client_dashboard.php" class="active" title="View your case overview, statistics, and recent activities">
                    <div class="button-content">
                        <i class="fas fa-home"></i>
                        <div class="text-content">
                            <span>Dashboard</span>
                            <small>Overview & Statistics</small>
                        </div>
                    </div>
                    
                </a>
            </li>
            <li>
                <a href="client_cases.php" title="Track your legal cases, view case details, and upload documents">
                    <div class="button-content">
                        <i class="fas fa-gavel"></i>
                        <div class="text-content">
                            <span>My Cases</span>
                            <small>Track Legal Cases</small>
                        </div>
                    </div>
                    
                </a>
            </li>
            <li>
                <a href="client_schedule.php" title="View your upcoming appointments, hearings, and court schedules">
                    <div class="button-content">
                        <i class="fas fa-calendar-alt"></i>
                        <div class="text-content">
                            <span>My Schedule</span>
                            <small>Appointments & Hearings</small>
                        </div>
                    </div>
                    
                </a>
            </li>
            <li>
                <a href="client_documents.php" title="Generate legal documents like affidavits and sworn statements">
                    <div class="button-content">
                        <i class="fas fa-file-alt"></i>
                        <div class="text-content">
                            <span>Document Generation</span>
                            <small>Create Legal Documents</small>
                        </div>
                    </div>
                    
                </a>
            </li>
            <li>
                <a href="client_messages.php" class="has-badge" title="Communicate with your attorney and legal team">
                    <div class="button-content">
                        <i class="fas fa-envelope"></i>
                        <div class="text-content">
                            <span>Messages</span>
                            <small>Chat with Attorney</small>
                        </div>
                    </div>
                    <span class="unread-message-badge hidden" id="unreadMessageBadge">0</span>
                </a>
            </li>
            <li>
                <a href="client_about.php" title="Learn more about Opiña Law Office and our team">
                    <div class="button-content">
                        <i class="fas fa-info-circle"></i>
                        <div class="text-content">
                            <span>About Us</span>
                            <small>Our Story & Team</small>
                        </div>
                    </div>
                    
                </a>
            </li>
        </ul>
    </div>
    <div class="main-content">
        <?php 
        $page_title = 'Client Dashboard';
        $page_subtitle = 'Overview of your cases and legal matters';
        include 'components/profile_header.php'; 
        ?>
        

        <!-- Statistics Cards -->
        <div class="dashboard-cards" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin-bottom: 2rem;">
            <div class="stat-card-modern" style="background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-radius: 16px; padding: 24px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); border: 1px solid rgba(229, 231, 235, 0.8); transition: all 0.3s ease; position: relative; overflow: hidden;">
                <div style="position: absolute; top: 0; right: 0; width: 80px; height: 80px; background: linear-gradient(135deg, rgba(93, 14, 38, 0.1), rgba(139, 21, 56, 0.05)); border-radius: 0 0 0 100%;"></div>
                <div style="display: flex; align-items: center; gap: 16px; position: relative; z-index: 1;">
                    <div style="width: 64px; height: 64px; border-radius: 16px; background: linear-gradient(135deg, #5D0E26, #8B1538); display: flex; align-items: center; justify-content: center; color: white; font-size: 1.8rem; box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);">
                        <i class="fas fa-gavel"></i>
                    </div>
                    <div style="flex: 1;">
                        <h3 style="margin: 0 0 4px 0; font-size: 0.9rem; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px;">Total Cases</h3>
                        <p style="margin: 0; font-size: 2rem; font-weight: 700; color: #1f2937; line-height: 1;"><?= number_format($total_cases) ?></p>
                    </div>
                </div>
            </div>
            <div class="stat-card-modern" style="background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-radius: 16px; padding: 24px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); border: 1px solid rgba(229, 231, 235, 0.8); transition: all 0.3s ease; position: relative; overflow: hidden;">
                <div style="position: absolute; top: 0; right: 0; width: 80px; height: 80px; background: linear-gradient(135deg, rgba(93, 14, 38, 0.1), rgba(139, 21, 56, 0.05)); border-radius: 0 0 0 100%;"></div>
                <div style="display: flex; align-items: center; gap: 16px; position: relative; z-index: 1;">
                    <div style="width: 64px; height: 64px; border-radius: 16px; background: linear-gradient(135deg, #5D0E26, #8B1538); display: flex; align-items: center; justify-content: center; color: white; font-size: 1.8rem; box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);">
                        <i class="fas fa-calendar-check"></i>
                    </div>
                    <div style="flex: 1;">
                        <h3 style="margin: 0 0 4px 0; font-size: 0.9rem; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px;">Upcoming Schedules</h3>
                        <p style="margin: 0; font-size: 2rem; font-weight: 700; color: #1f2937; line-height: 1;"><?= number_format($upcoming_hearings) ?></p>
                    </div>
                </div>
            </div>
            <div class="stat-card-modern" style="background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%); border-radius: 16px; padding: 24px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); border: 1px solid rgba(229, 231, 235, 0.8); transition: all 0.3s ease; position: relative; overflow: hidden;">
                <div style="position: absolute; top: 0; right: 0; width: 80px; height: 80px; background: linear-gradient(135deg, rgba(93, 14, 38, 0.1), rgba(139, 21, 56, 0.05)); border-radius: 0 0 0 100%;"></div>
                <div style="display: flex; align-items: center; gap: 16px; position: relative; z-index: 1;">
                    <div style="width: 64px; height: 64px; border-radius: 16px; background: linear-gradient(135deg, #5D0E26, #8B1538); display: flex; align-items: center; justify-content: center; color: white; font-size: 1.8rem; box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div style="flex: 1;">
                        <h3 style="margin: 0 0 4px 0; font-size: 0.9rem; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px;">Completed Cases</h3>
                        <p style="margin: 0; font-size: 2rem; font-weight: 700; color: #1f2937; line-height: 1;"><?= number_format($completed_cases) ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Announcements and Weather Container -->
        <div style="display: grid; grid-template-columns: 1fr calc(33.333% - 16px); gap: 24px; margin-bottom: 32px; align-items: stretch;">
            <!-- Announcements Container -->
            <div class="dashboard-graph" style="grid-column: 1;">
                <h3><i class="fas fa-bullhorn"></i> Announcements</h3>
                <?php if (count($announcements) > 0): ?>
                    <div id="announcementCarousel" style="position: relative;">
                        <?php foreach ($announcements as $index => $announcement): ?>
                            <div class="announcement-slide" style="display: <?= $index === 0 ? 'block' : 'none' ?>;">
                                <!-- Content Above Image -->
                                <div style="text-align: left; margin-bottom: 16px;">
                                    <p style="color: #555; line-height: 1.6; margin: 0;">
                                        <?= htmlspecialchars($announcement['description']) ?>
                                    </p>
                                </div>
                                
                                <!-- Large Image -->
                                <div style="width: 100%; height: 400px; border-radius: 12px; overflow: hidden; cursor: pointer; position: relative;" onclick="openImageModal('<?= htmlspecialchars($announcement['image_path']) ?>')">
                                    <?php if ($announcement['image_path'] && file_exists($announcement['image_path'])): ?>
                                        <img src="<?= htmlspecialchars($announcement['image_path']) ?>" alt="Announcement Image" style="width: 100%; height: 100%; object-fit: contain;">
                                        <!-- Zoom Icon Overlay -->
                                        <div style="position: absolute; top: 10px; right: 10px; background: rgba(0,0,0,0.6); color: white; padding: 8px; border-radius: 50%; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; font-size: 14px;">
                                            <i class="fas fa-search-plus"></i>
                                        </div>
                                    <?php else: ?>
                                        <div style="width: 100%; height: 100%; background: var(--gradient-primary); display: flex; align-items: center; justify-content: center; color: white; font-size: 4rem;">
                                            <i class="fas fa-image"></i>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                        
                        <!-- Navigation Buttons -->
                        <?php if (count($announcements) > 1): ?>
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px;">
                                <button onclick="previousAnnouncement()" class="nav-btn" style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 8px 16px; cursor: pointer; color: #666; transition: all 0.2s;">
                                    <i class="fas fa-chevron-left"></i> Previous
                                </button>
                                <div style="display: flex; gap: 8px;">
                                    <?php for ($i = 0; $i < count($announcements); $i++): ?>
                                        <button onclick="goToAnnouncement(<?= $i ?>)" class="nav-dot" style="width: 8px; height: 8px; border-radius: 50%; border: none; background: <?= $i === 0 ? 'var(--primary-color)' : '#e9ecef' ?>; cursor: pointer; transition: all 0.2s;"></button>
                                    <?php endfor; ?>
                                </div>
                                <button onclick="nextAnnouncement()" class="nav-btn" style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 8px 16px; cursor: pointer; color: #666; transition: all 0.2s;">
                                    Next <i class="fas fa-chevron-right"></i>
                                </button>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <div style="text-align: center; padding: 40px; color: #666;">
                        <i class="fas fa-bullhorn" style="font-size: 3rem; margin-bottom: 16px; opacity: 0.3;"></i>
                        <p>No announcements available</p>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Weather Container -->
            <div class="dashboard-graph" style="grid-column: 2;">
                <h3><i class="fas fa-cloud-sun"></i> Weather</h3>
                <div style="background: white; border-radius: 12px; padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; height: 100%; border: 1px solid #e5e7eb; display: flex; flex-direction: column;">
                    <!-- Weather Icon -->
                    <div style="font-size: 2.5rem; color: #8B1538; margin-bottom: 16px;">
                        <i class="fas fa-cloud-sun"></i>
                    </div>
                    
                    <!-- Temperature -->
                    <div style="font-size: 2rem; font-weight: 600; color: #333; margin-bottom: 8px;">
                        28°C
                    </div>
                    
                    <!-- Weather Description -->
                    <div style="color: #666; margin-bottom: 20px; font-weight: 400; font-size: 0.95rem;">
                        Partly Cloudy
                    </div>
                    
                    <!-- Location -->
                    <div style="color: #888; margin-bottom: auto; font-size: 0.85rem;">
                        <i class="fas fa-map-marker-alt" style="margin-right: 5px;"></i>
                        Cabuyao, Laguna
                    </div>
                    
                    <!-- Weather Details -->
                    <div style="border-top: 1px solid #f0f0f0; padding: 16px 0 24px 0; margin-top: auto;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span style="color: #666; font-size: 0.85rem;">
                                Feels like
                            </span>
                            <span style="font-weight: 500; font-size: 0.85rem; color: #333;">30°C</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span style="color: #666; font-size: 0.85rem;">
                                Humidity
                            </span>
                            <span style="font-weight: 500; font-size: 0.85rem; color: #333;">65%</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span style="color: #666; font-size: 0.85rem;">
                                Wind Speed
                            </span>
                            <span style="font-weight: 500; font-size: 0.85rem; color: #333;">12 km/h</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span style="color: #666; font-size: 0.85rem;">
                                Visibility
                            </span>
                            <span style="font-weight: 500; font-size: 0.85rem; color: #333;">10 km</span>
                        </div>
                        
                        <!-- Update Time -->
                        <div style="margin-top: 16px; color: #999; font-size: 0.75rem;">
                            Last updated: 2 minutes ago
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div style="display: grid; grid-template-columns: 1fr; gap: 24px; margin-bottom: 20px;">
            <div style="width: 100%; display: block; margin-bottom: 20px; background: #800000; border-radius: 12px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25); padding: 24px;">
                <div style="text-align: center; margin-bottom: 24px;">
                    <h2 style="font-size: 1.8rem; font-weight: 700; color: #ffffff; margin-bottom: 8px; display: flex; align-items: center; justify-content: center; gap: 12px;">
                        <i class="fas fa-chart-pie"></i> Case Status Overview
                    </h2>
                </div>
                <div style="background: rgba(255, 255, 255, 0.95); border-radius: 12px; padding: 24px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);">
                    <div class="chart-container">
                        <canvas id="caseStatusChart"></canvas>
                        <?php 
                        $pie_total = array_sum($status_counts);
                        // Show overlay ONLY for sample data (total = 25)
                        if ($pie_total == 25): ?>
                        <div class="sample-data-overlay">
                            <i class="fas fa-info-circle"></i>
                            <span>Sample data shown</span>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Activities -->
        <div style="width: 100%; display: block; margin-bottom: 20px; background: #800000; border-radius: 12px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25); padding: 24px;">
            <div style="text-align: center; margin-bottom: 24px;">
                <h2 style="font-size: 1.8rem; font-weight: 700; color: #ffffff; margin-bottom: 8px; display: flex; align-items: center; justify-content: center; gap: 12px;">
                    <i class="fas fa-clock"></i> Recent Activities
                </h2>
            </div>
            <div style="background: rgba(255, 255, 255, 0.95); border-radius: 12px; padding: 24px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15); max-height: 400px; overflow-y: auto;">
                <?php if (count($recent_activities) > 0): ?>
                    <?php foreach ($recent_activities as $activity): 
                        // Determine icon based on activity type
                        $icon = 'info-circle';
                        $icon_class = 'fas fa-' . ($activity['icon'] ?? 'info-circle');
                        if (isset($activity['icon'])) {
                            $icon_class = 'fas fa-' . $activity['icon'];
                        } else {
                            // Fallback based on type
                            switch(strtolower($activity['type'])) {
                                case 'case':
                                    $icon_class = 'fas fa-gavel';
                                    break;
                                case 'request':
                                    $icon_class = 'fas fa-file-alt';
                                    break;
                                case 'message':
                                    $icon_class = 'fas fa-comment';
                                    break;
                                case 'document':
                                    $icon_class = 'fas fa-file-pdf';
                                    break;
                                default:
                                    $icon_class = 'fas fa-info-circle';
                            }
                        }
                    ?>
                        <div style="display: flex; align-items: center; padding: 16px; border-bottom: 1px solid #f0f0f0; transition: background 0.2s;" onmouseover="this.style.background='#f8f9fa'" onmouseout="this.style.background='transparent'">
                            <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #5D0E26, #8B1538); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; margin-right: 16px;">
                                <i class="<?= $icon_class ?>"></i>
                            </div>
                            <div style="flex: 1;">
                                <div style="font-weight: 600; color: #5D0E26; margin-bottom: 4px;">
                                    <?= htmlspecialchars($activity['title']) ?>
                                </div>
                                <div style="font-size: 0.9rem; color: #666;">
                                    <?= ucfirst($activity['type']) ?> • <?= date('M j, Y g:i A', strtotime($activity['date'])) ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div style="text-align: center; padding: 40px; color: #666;">
                        <i class="fas fa-inbox" style="font-size: 3rem; margin-bottom: 16px; opacity: 0.3;"></i>
                        <p>No recent activities</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Image Zoom Modal -->
    <div id="imageModal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.9); cursor: pointer;" onclick="closeImageModal()">
        <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); max-width: 90%; max-height: 90%;">
            <img id="modalImage" src="" alt="Zoomed Image" style="width: 100%; height: auto; border-radius: 8px;">
        </div>
        <div style="position: absolute; top: 20px; right: 30px; color: white; font-size: 30px; font-weight: bold; cursor: pointer;" onclick="closeImageModal()">
            <i class="fas fa-times"></i>
        </div>
    </div>

    <script>
        // Case Status Chart
        const ctx = document.getElementById('caseStatusChart').getContext('2d');
        const caseStatusData = {
            labels: <?= json_encode(array_keys($status_counts)) ?>,
            datasets: [{
                data: <?= json_encode(array_values($status_counts)) ?>,
                backgroundColor: [
                    '#5D0E26', '#27ae60', '#3498db', '#f39c12', '#e74c3c', '#9b59b6', '#8B1538', '#8B4A6B'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        };
        
        const caseStatusChart = new Chart(ctx, {
            type: 'doughnut',
            data: caseStatusData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true,
                            font: {
                                size: 12
                            }
                        }
                    }
                },
                elements: {
                    arc: {
                        borderWidth: 3
                    }
                }
            }
        });

        // Fix chart responsiveness on window resize
        window.addEventListener('resize', function() {
            caseStatusChart.resize();
        });

        // Force chart resize after page load
        setTimeout(function() {
            caseStatusChart.resize();
        }, 100);

        // Announcement Carousel
        let currentAnnouncement = 0;
        const announcements = <?= json_encode($announcements) ?>;
        
        function showAnnouncement(index) {
            const slides = document.querySelectorAll('.announcement-slide');
            const dots = document.querySelectorAll('.nav-dot');
            
            // Hide all slides
            slides.forEach(slide => slide.style.display = 'none');
            
            // Show current slide
            if (slides[index]) {
                slides[index].style.display = 'block';
            }
            
            // Update dots
            dots.forEach((dot, i) => {
                dot.style.background = i === index ? 'var(--primary-color)' : '#e9ecef';
            });
            
            currentAnnouncement = index;
        }
        
        function nextAnnouncement() {
            const nextIndex = (currentAnnouncement + 1) % announcements.length;
            showAnnouncement(nextIndex);
        }
        
        function previousAnnouncement() {
            const prevIndex = currentAnnouncement === 0 ? announcements.length - 1 : currentAnnouncement - 1;
            showAnnouncement(prevIndex);
        }
        
        function goToAnnouncement(index) {
            showAnnouncement(index);
        }
        
        // Add hover effects for navigation buttons
        document.addEventListener('DOMContentLoaded', function() {
            const navBtns = document.querySelectorAll('.nav-btn');
            navBtns.forEach(btn => {
                btn.addEventListener('mouseenter', function() {
                    this.style.background = '#e9ecef';
                    this.style.color = '#333';
                });
                btn.addEventListener('mouseleave', function() {
                    this.style.background = '#f8f9fa';
                    this.style.color = '#666';
                });
            });
        });

        // Image Zoom Modal Functions
        function openImageModal(imageSrc) {
            if (!imageSrc) {
                alert('No image to display');
                return;
            }
            
            const modal = document.getElementById('imageModal');
            const modalImg = document.getElementById('modalImage');
            
            if (modal && modalImg) {
                modal.style.display = 'block';
                modalImg.src = imageSrc;
                modalImg.onload = function() {
                    console.log('Image loaded successfully');
                };
                modalImg.onerror = function() {
                    console.error('Failed to load image:', imageSrc);
                    alert('Failed to load image');
                };
                
                // Prevent body scroll when modal is open
                document.body.style.overflow = 'hidden';
            } else {
                console.error('Modal elements not found');
                alert('Modal not found');
            }
        }

        function closeImageModal() {
            const modal = document.getElementById('imageModal');
            if (modal) {
                modal.style.display = 'none';
                // Restore body scroll
                document.body.style.overflow = 'auto';
            }
        }

        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeImageModal();
            }
        });

    </script>

    <!-- Logout Confirmation Modal -->
    <div id="logoutConfirmModal" style="display: none; position: fixed; z-index: 10005; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); backdrop-filter: blur(8px); align-items: center; justify-content: center;">
        <div style="background: white; border-radius: 16px; width: 90%; max-width: 420px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); overflow: hidden; animation: modalFadeIn 0.3s ease;">
            <!-- Modal Header -->
            <div style="background: linear-gradient(135deg, #5D0E26 0%, #8B1538 100%); padding: 20px 24px;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div style="width: 40px; height: 40px; background: rgba(255,255,255,0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center;">
                        <i class="fas fa-sign-out-alt" style="color: white; font-size: 18px;"></i>
                    </div>
                    <div>
                        <h2 style="color: white; margin: 0; font-size: 1.3em; font-weight: 700;">Confirm Logout</h2>
                        <p style="color: rgba(255,255,255,0.9); margin: 2px 0 0 0; font-size: 0.85em;">Security Notice</p>
                    </div>
                </div>
            </div>
            
            <!-- Modal Content -->
            <div style="padding: 24px;">
                <p style="color: #2c3e50; margin: 0 0 16px 0; font-size: 15px; line-height: 1.6;">
                    Are you sure you want to logout?
                </p>
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px 16px; border-radius: 4px; margin-bottom: 20px;">
                    <p style="margin: 0; font-size: 13px; color: #856404; font-weight: 500;">
                        <i class="fas fa-exclamation-triangle" style="margin-right: 6px;"></i>
                        You will need to change your password on your next login.
                    </p>
                </div>
                
                <!-- Action Buttons -->
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button onclick="closeLogoutModal();" style="padding: 10px 24px; border: 2px solid #e5e7eb; background: white; border-radius: 8px; cursor: pointer; font-weight: 600; color: #374151; transition: all 0.3s ease; font-size: 14px;" onmouseover="this.style.borderColor='#d1d5db'; this.style.background='#f9fafb'" onmouseout="this.style.borderColor='#e5e7eb'; this.style.background='white'">Cancel</button>
                    <button onclick="confirmLogout();" style="padding: 10px 24px; background: linear-gradient(135deg, #5D0E26, #8B1538); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; transition: all 0.3s ease; font-size: 14px; box-shadow: 0 2px 8px rgba(93, 14, 38, 0.3);" onmouseover="this.style.background='linear-gradient(135deg, #8B1538, #5D0E26)'; this.style.transform='translateY(-1px)'; this.style.boxShadow='0 4px 12px rgba(93, 14, 38, 0.4)'" onmouseout="this.style.background='linear-gradient(135deg, #5D0E26, #8B1538)'; this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 8px rgba(93, 14, 38, 0.3)'">Logout</button>
                </div>
            </div>
        </div>
    </div>

    <!-- First-Time Login Password Change Modal -->
    <div id="firstLoginModal" style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0, 0, 0, 0.5); backdrop-filter: blur(5px); display: none; align-items: center; justify-content: center; z-index: 10002;">
        <div style="background: #fff; border-radius: 12px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); padding: 0; max-width: 400px; width: 90%; position: relative; animation: modalSlideIn 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94); overflow: hidden;">
            
            <!-- Modal Header -->
            <div style="background: linear-gradient(135deg, #5D0E26, #8B1538); color: white; padding: 20px; text-align: center; position: relative;">
                <div style="width: 50px; height: 50px; background: rgba(255, 255, 255, 0.2); border-radius: 50%; margin: 0 auto 15px; display: flex; align-items: center; justify-content: center;">
                    <i class="fas fa-key" style="color: white; font-size: 20px;"></i>
                </div>
                <h2 style="font-family: 'Playfair Display', serif; font-size: 20px; font-weight: 700; margin: 0 0 5px 0; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);">Change Password Now</h2>
                <p style="font-size: 14px; font-weight: 500; opacity: 0.9; margin: 0;">Security Requirement</p>
            </div>

            <!-- Modal Body -->
            <div style="padding: 25px; text-align: center;">
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; border-radius: 0 8px 8px 0; margin-bottom: 20px; text-align: left;">
                    <h4 style="color: #856404; margin: 0 0 8px 0; font-size: 14px; font-weight: 600;">
                        <i class="fas fa-exclamation-triangle" style="margin-right: 6px;"></i>
                        Security Notice
                    </h4>
                    <p style="color: #856404; margin: 0; font-size: 12px; line-height: 1.4;">
                        For security purposes, you must change your password before accessing the system. 
                        This is a one-time requirement for all new accounts.
                    </p>
                </div>
                
                <p style="color: #5D0E26; font-size: 16px; font-weight: 600; margin: 0 0 10px 0; line-height: 1.4;">
                    Welcome to Opiña Law Office!
                </p>
                <p style="color: #666; font-size: 14px; margin: 0 0 25px 0; line-height: 1.5;">
                    Please change your password to continue using your dashboard.
                </p>
                
                <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
                    <button onclick="redirectToProfilePasswordChange();" 
                            style="background: linear-gradient(135deg, #5D0E26, #8B1538); color: white; border: none; padding: 12px 25px; font-size: 14px; font-weight: 600; border-radius: 6px; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);">
                        <i class="fas fa-key" style="margin-right: 6px;"></i>
                        Change Password
                    </button>
                    <button onclick="showLogoutModal();" 
                            style="background: #6c757d; color: white; border: none; padding: 12px 25px; font-size: 14px; font-weight: 600; border-radius: 6px; cursor: pointer; transition: all 0.3s ease;">
                        <i class="fas fa-sign-out-alt" style="margin-right: 6px;"></i>
                        Logout
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        // First-Time Login Modal Functions
        function showFirstLoginModal() {
            const modal = document.getElementById('firstLoginModal');
            modal.style.display = 'flex';
        }

        function closeFirstLoginModal() {
            const modal = document.getElementById('firstLoginModal');
            modal.style.display = 'none';
        }

        function redirectToProfilePasswordChange() {
            // Close the first-time login modal
            closeFirstLoginModal();
            
            // Call the existing changePassword function from profile header
            setTimeout(() => {
                if (typeof changePassword === 'function') {
                    changePassword();
                } else {
                    // Fallback: try to find and click the change password link
                    const passwordChangeLink = document.querySelector('a[onclick*="changePassword"]');
                    if (passwordChangeLink) {
                        passwordChangeLink.click();
                    }
                }
            }, 100);
        }

        // Logout Modal Functions
        function showLogoutModal() {
            const modal = document.getElementById('logoutConfirmModal');
            modal.style.display = 'flex';
        }

        function closeLogoutModal() {
            const modal = document.getElementById('logoutConfirmModal');
            modal.style.display = 'none';
        }

        function confirmLogout() {
            // Close the logout modal
            closeLogoutModal();
            
            // Log out the user
            fetch('logout.php', {
                method: 'POST'
            })
            .then(() => {
                window.location.href = 'login_form.php';
            })
            .catch(error => {
                console.error('Error:', error);
                window.location.href = 'login_form.php';
            });
        }

        // Legacy function for compatibility
        function logoutUser() {
            showLogoutModal();
        }

        // Show modal if this is a first-time login AND account was created by attorney/admin
        <?php if ($show_password_modal): ?>
        document.addEventListener('DOMContentLoaded', function() {
            showFirstLoginModal();
        });
        <?php endif; ?>
    </script>

    <script>
        // Hamburger Menu Functionality
        const hamburgerMenu = document.getElementById('hamburgerMenu');
        const sidebar = document.getElementById('sidebar');
        const sidebarOverlay = document.getElementById('sidebarOverlay');
        const headerContainer = document.querySelector('.main-content .header');
        const sidebarCloseBtn = document.getElementById('sidebarCloseBtn');

        if (headerContainer && hamburgerMenu && !headerContainer.contains(hamburgerMenu)) {
            headerContainer.insertBefore(hamburgerMenu, headerContainer.firstElementChild);
        }

        const hamburgerIcon = hamburgerMenu ? hamburgerMenu.querySelector('i') : null;

        // Toggle sidebar
        function toggleSidebar() {
            if (!sidebar || !sidebarOverlay) return;

            sidebar.classList.toggle('active');
            sidebarOverlay.classList.toggle('active');
            
            // Toggle icon
            if (!hamburgerIcon) return;

            if (sidebar.classList.contains('active')) {
                hamburgerIcon.classList.remove('fa-bars');
                hamburgerIcon.classList.add('fa-times');
            } else {
                hamburgerIcon.classList.remove('fa-times');
                hamburgerIcon.classList.add('fa-bars');
            }
        }

        // Close sidebar
        function closeSidebar() {
            if (!sidebar || !sidebarOverlay) return;

            sidebar.classList.remove('active');
            sidebarOverlay.classList.remove('active');

            if (!hamburgerIcon) return;

            hamburgerIcon.classList.remove('fa-times');
            hamburgerIcon.classList.add('fa-bars');
        }

        // Event listeners
        if (hamburgerMenu) {
            hamburgerMenu.addEventListener('click', toggleSidebar);
        }
        if (sidebarOverlay) {
            sidebarOverlay.addEventListener('click', closeSidebar);
        }
        if (sidebarCloseBtn) {
            sidebarCloseBtn.addEventListener('click', closeSidebar);
        }

        // Close sidebar when clicking on a menu item (on mobile)
        if (sidebar) {
            const sidebarLinks = sidebar.querySelectorAll('.sidebar-menu a');
            sidebarLinks.forEach(link => {
                link.addEventListener('click', function() {
                    if (window.innerWidth <= 768) {
                        closeSidebar();
                    }
                });
            });
        }

        // Close sidebar on window resize to desktop
        window.addEventListener('resize', function() {
            if (window.innerWidth > 768) {
                closeSidebar();
            }
        });

        // Close sidebar with Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && sidebar && sidebar.classList.contains('active')) {
                closeSidebar();
            }
        });
    </script>
</body>
</html> 
