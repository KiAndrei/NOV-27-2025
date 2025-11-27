<?php
require_once 'session_manager.php';
validateUserAccess('admin');
require_once 'config.php';
require_once 'audit_logger.php';
require_once 'security_monitor.php';
require_once 'action_logger_helper.php';


$admin_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT profile_image FROM user_form WHERE id=?");
$stmt->bind_param("i", $admin_id);
$stmt->execute();
$res = $stmt->get_result();
$profile_image = '';
if ($res && $row = $res->fetch_assoc()) {
    $profile_image = $row['profile_image'];
}
if (!$profile_image || !file_exists($profile_image)) {
        $profile_image = 'images/default-avatar.jpg';
    }

// Check if audit_trail table exists
$tableExists = $conn->query("SHOW TABLES LIKE 'audit_trail'")->num_rows > 0;

// Get filters from URL parameters
$userType = $_GET['user_type'] ?? 'all';
$module = $_GET['module'] ?? 'all';
$status = $_GET['status'] ?? 'all';
$priority = $_GET['priority'] ?? 'all';
$dateFrom = $_GET['date_from'] ?? '';
$dateTo = $_GET['date_to'] ?? '';
$search = $_GET['search'] ?? '';

// Pagination parameters
$page = max(1, intval($_GET['page'] ?? 1));
$recordsPerPage = 100;
$offset = ($page - 1) * $recordsPerPage;

// Apply filters
$filters = [
    'user_type' => $userType,
    'module' => $module,
    'status' => $status,
    'priority' => $priority,
    'date_from' => $dateFrom,
    'date_to' => $dateTo,
    'search' => $search,
    'limit' => $recordsPerPage,
    'offset' => $offset
];

// Get audit trail data and stats if table exists
$auditData = [];
$auditStats = [];
$securityStats = [];
$modules = [];
$totalRecords = 0;
$totalPages = 0;

if ($tableExists) {
    $totalRecords = $auditLogger->getAuditTrailCount($filters);
    $totalPages = ceil($totalRecords / $recordsPerPage);
    $auditData = $auditLogger->getAuditTrail($filters);
    $auditStats = $auditLogger->getAuditStats();
    $securityStats = getSecurityStatistics();
    
    // Get unique modules for filter
    $modulesQuery = $conn->query("SELECT DISTINCT module FROM audit_trail ORDER BY module");
    while ($row = $modulesQuery->fetch_assoc()) {
        $modules[] = $row['module'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Trail - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?= time() ?>">
    <style>
        html, body { overflow-x: hidden; }
        .sidebar { transition: transform 0.3s ease; overflow-x: hidden; }
        .sidebar,
        body .sidebar {
            display: flex;
            flex-direction: column;
        }
        .sidebar-header,
        body .sidebar-header {
            display: flex !important;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }
        .sidebar-header img,
        body .sidebar-header img {
            margin-left: auto !important;
            margin-right: auto !important;
        }
        .sidebar-header h2,
        body .sidebar-header h2 {
            width: 100%;
        }
        .sidebar-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.35);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
            z-index: 950;
        }
        .sidebar-overlay.visible {
            opacity: 1;
            pointer-events: auto;
        }
        .mobile-nav-toggle {
            display: none;
            align-items: center;
            gap: 8px;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: #fff;
            border: none;
            border-radius: 10px;
            padding: 10px 16px;
            font-size: 0.95rem;
            font-weight: 600;
            margin: 0;
            cursor: pointer;
            box-shadow: 0 8px 20px rgba(93, 14, 38, 0.25);
            transition: transform 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
            position: relative;
            z-index: 1200;
        }
        .mobile-nav-toggle i {
            font-size: 1rem;
        }
        .mobile-nav-toggle:focus-visible {
            outline: 3px solid rgba(93, 14, 38, 0.35);
            outline-offset: 2px;
        }
        .mobile-nav-toggle:hover {
            transform: translateY(-1px);
            box-shadow: 0 10px 24px rgba(93, 14, 38, 0.3);
        }
        .sidebar-close-btn {
            display: none;
            position: absolute;
            top: 12px;
            right: 12px;
            width: 36px;
            height: 36px;
            border: none;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.2);
            color: #fff;
            cursor: pointer;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
            transition: background 0.2s ease, transform 0.2s ease;
        }
        .sidebar-close-btn:hover {
            background: rgba(255, 255, 255, 0.35);
            transform: scale(1.05);
        }
        @media (max-width: 1200px) {
            .stats-grid {
                grid-template-columns: repeat(3, 1fr);
            }
        }
        @media (max-width: 1024px) {
            .sidebar {
                position: fixed;
                inset: 0 auto 0 0;
                width: 260px;
                max-width: 80%;
                height: 100%;
                background: var(--gradient-primary, linear-gradient(135deg, #5D0E26, #8B1538));
                color: #fff;
                transform: translateX(-100%);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                z-index: 10000;
                box-shadow: 6px 0 18px rgba(0, 0, 0, 0.15);
                overflow-y: auto;
                -webkit-overflow-scrolling: touch;
                overflow-x: hidden;
            }
            body.sidebar-open .sidebar {
                transform: translateX(0);
            }
            body.sidebar-open {
                overflow: hidden;
            }
            .main-content {
                margin-left: 0 !important;
                max-width: 100% !important;
                padding: 18px 16px 28px 16px;
                box-sizing: border-box;
            }
            .mobile-nav-toggle {
                display: inline-flex;
            }
            .sidebar-close-btn {
                display: flex;
            }
            .filters-section,
            .audit-table-container {
                padding: 18px;
            }
        }
        .audit-container {
            padding: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.admin {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .stat-card.attorney {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        .stat-card.employee {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }
        
        .stat-card.client {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }
        
        .stat-card.security {
            background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%);
        }
        
        .stat-number {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .stat-label {
            font-size: 0.75rem;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-details {
            margin-top: 8px;
            opacity: 0.8;
            font-size: 0.65rem;
        }
        
        .filters-section {
            background: white;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
        }
        
        .filters-section h3 {
            font-size: 1.1rem;
            margin-bottom: 15px;
            color: #333;
        }
        
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 15px;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
        }
        
        .filter-group label {
            font-weight: 600;
            margin-bottom: 5px;
            color: #333;
            font-size: 0.85rem;
        }
        
        .filter-group select,
        .filter-group input {
            padding: 8px 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 0.85rem;
            background: white;
            transition: border-color 0.3s ease;
        }
        
        .filter-group select:focus,
        .filter-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .filter-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .btn-filter {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85rem;
            transition: all 0.3s ease;
        }
        
        .btn-filter:hover {
            background: #5a6fd8;
            transform: translateY(-2px);
        }
        
        .btn-reset {
            background: #6c757d;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85rem;
            text-decoration: none;
            transition: all 0.3s ease;
        }
        
        .btn-reset:hover {
            background: #5a6268;
        }
        
        .audit-table-container {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            overflow-x: auto;
        }
        
        .table-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }
        
        .table-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: #333;
        }
        
        .table-actions {
            display: flex;
            gap: 15px;
        }
        
        .btn-export {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 12px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(40, 167, 69, 0.3);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-export:hover {
            background: linear-gradient(135deg, #218838 0%, #1ea085 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
        }
        
        .btn-export:active {
            transform: translateY(0);
            box-shadow: 0 2px 10px rgba(40, 167, 69, 0.3);
        }
        
        
        /* Pagination Styles */
        .pagination-container {
            margin-top: 30px;
            padding: 20px 0;
            border-top: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .pagination-info {
            color: #6c757d;
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .pagination-controls {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .pagination-numbers {
            display: flex;
            gap: 4px;
            margin: 0 10px;
        }
        
        .pagination-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 8px 12px;
            border: 1px solid #dee2e6;
            background: white;
            color: #495057;
            text-decoration: none;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s ease;
            cursor: pointer;
            min-width: 40px;
            justify-content: center;
        }
        
        .pagination-btn:hover:not(.pagination-disabled):not(.pagination-current) {
            background: #f8f9fa;
            border-color: #adb5bd;
            color: #212529;
            transform: translateY(-1px);
        }
        
        .pagination-current {
            background: linear-gradient(135deg, #5D0E26 0%, #8B1538 100%);
            color: white;
            border-color: #5D0E26;
            font-weight: 600;
        }
        
        .pagination-disabled {
            background: #f8f9fa;
            color: #adb5bd;
            border-color: #e9ecef;
            cursor: not-allowed;
        }
        
        .pagination-first,
        .pagination-last {
            font-weight: 600;
        }
        
        .pagination-prev,
        .pagination-next {
            font-weight: 600;
        }
        
        .audit-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .audit-table th {
            background: #f8f9fa;
            padding: 10px 8px;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            font-size: 0.85rem;
        }
        
        .audit-table td {
            padding: 8px;
            border-bottom: 1px solid #dee2e6;
            vertical-align: middle;
            font-size: 0.8rem;
        }
        
        .audit-table tr:hover {
            background: #f8f9fa;
        }
        
        .user-type-badge {
            padding: 3px 6px;
            border-radius: 12px;
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .user-type-badge.admin {
            background: #f093fb;
            color: white;
        }
        
        .user-type-badge.attorney {
            background: #4facfe;
            color: white;
        }
        
        .user-type-badge.employee {
            background: #43e97b;
            color: white;
        }
        
        .user-type-badge.client {
            background: #fa709a;
            color: white;
        }
        
        .status-badge {
            padding: 3px 6px;
            border-radius: 12px;
            font-size: 0.65rem;
            font-weight: 600;
        }
        
        .status-success {
            background: #d4edda;
            color: #155724;
        }
        
        .status-failed {
            background: #f8d7da;
            color: #721c24;
        }
        
        .status-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .status-info {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .module-badge {
            background: #e9ecef;
            color: #495057;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 0.7rem;
            font-weight: 500;
        }
        
        .timestamp {
            color: #6c757d;
            font-size: 0.75rem;
        }
        
        .audit-table .user-info {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .audit-table .user-info > div {
            display: flex;
            flex-direction: row;
            align-items: center;
            gap: 6px;
        }
        
        .no-data {
            text-align: center;
            padding: 50px;
            color: #6c757d;
        }
        
        .no-data i {
            font-size: 3rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }
        
        .setup-notice {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 30px;
        }
        
        .setup-notice h2 {
            margin-bottom: 15px;
            font-size: 1.8rem;
        }
        
        .setup-notice p {
            margin-bottom: 20px;
            opacity: 0.9;
            font-size: 1.1rem;
        }
        
        .btn-setup {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 2px solid rgba(255,255,255,0.3);
            padding: 12px 30px;
            border-radius: 25px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn-setup:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        
        @media (max-width: 768px) {
            .filters-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .mobile-nav-toggle {
                position: absolute;
                left: 16px;
                top: 16px;
                width: auto;
                justify-content: center;
            }
            .header {
                position: relative;
                padding-left: 56px;
                flex-direction: row;
                align-items: center;
                gap: 16px;
            }
            .header-title {
                flex: 1;
                text-align: center;
            }
            .header-title h1 {
                width: 100%;
                text-align: center;
            }
            .header-title p {
                display: none;
            }
            .header .user-info {
                margin-left: auto;
                align-items: center !important;
                gap: 12px !important;
            }
            .header .user-details {
                display: none !important;
            }
            
            .table-header {
                flex-direction: column;
                gap: 15px;
                align-items: flex-start;
            }
            
            .table-actions {
                width: 100%;
                justify-content: flex-start;
                flex-wrap: wrap;
                gap: 10px;
            }
            
            .btn-export {
                padding: 10px 20px;
                font-size: 0.85rem;
                flex: 1;
                min-width: 120px;
                justify-content: center;
            }
            
            .pagination-container {
                flex-direction: column;
                align-items: center;
                gap: 20px;
            }
            
            .pagination-controls {
                justify-content: center;
            }
            
            .pagination-btn {
                padding: 6px 10px;
                font-size: 0.8rem;
                min-width: 35px;
            }
            
            .pagination-numbers {
                margin: 0 5px;
            }
            
            .audit-table {
                font-size: 0.9rem;
            }
            
            .audit-table th,
            .audit-table td {
                padding: 10px 8px;
            }
        }
        
        @media (max-width: 480px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            .main-content {
                padding: 64px 12px 20px 12px;
            }
            .table-actions {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar" id="adminSidebar">
        <div class="sidebar-header">
            <img src="images/logo.jpg" alt="Logo">
            <h2>Opiña Law Office</h2>
        </div>
        <button class="sidebar-close-btn" type="button" aria-label="Close sidebar">
            <i class="fas fa-times"></i>
        </button>
        <ul class="sidebar-menu">
            <li><a href="admin_dashboard.php"><i class="fas fa-home"></i><span>Dashboard</span></a></li>
            <li><a href="admin_managecases.php"><i class="fas fa-gavel"></i><span>Case Management</span></a></li>
            <li><a href="admin_documents.php"><i class="fas fa-file-alt"></i><span>Document Storage</span></a></li>
            <li><a href="admin_schedule.php"><i class="fas fa-calendar-alt"></i><span>Scheduling</span></a></li>
            <li><a href="admin_audit.php" class="active"><i class="fas fa-history"></i><span>Audit Trail</span></a></li>
            <li><a href="admin_efiling.php"><i class="fas fa-paper-plane"></i><span>E-Filing</span></a></li>
            <li><a href="admin_document_generation.php"><i class="fas fa-file-alt"></i><span>Document Generation</span></a></li>
            <li><a href="admin_usermanagement.php"><i class="fas fa-users-cog"></i><span>User Management</span></a></li>
            <li><a href="admin_clients.php"><i class="fas fa-users"></i><span>Client Management</span></a></li>
            <li><a href="admin_messages.php" class="has-badge"><i class="fas fa-comments"></i><span>Messages</span><span class="unread-message-badge hidden" id="unreadMessageBadge">0</span></a></li>
        </ul>
    </div>

    <div class="sidebar-overlay" id="sidebarOverlay"></div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Header -->
        <?php 
        $page_title = 'Audit Trail';
        $page_subtitle = 'Comprehensive tracking of all system activities and user actions';
        include 'components/profile_header.php'; 
        ?>
        <button class="mobile-nav-toggle" id="mobileNavToggle" aria-label="Toggle navigation" aria-controls="adminSidebar" aria-expanded="false" type="button">
            <i class="fas fa-bars"></i>
        </button>

        <div class="audit-container">
            <?php if (!$tableExists): ?>
                <!-- Setup Notice -->
                <div class="setup-notice">
                    <h2><i class="fas fa-database"></i> Audit Trail Setup Required</h2>
                    <p>The audit trail system needs to be set up in your database first.</p>
                    <p>Please import the updated <code>lawfirm.sql</code> file in phpMyAdmin to create the required tables.</p>
                    <a href="#" onclick="showSetupInstructions()" class="btn-setup">
                        <i class="fas fa-info-circle"></i> View Setup Instructions
                    </a>
                </div>
            <?php else: ?>
                <!-- Statistics Dashboard -->
                <div class="stats-grid">
                    <div class="stat-card admin">
                        <div class="stat-number"><?= $auditStats['by_user_type']['admin'] ?? 0 ?></div>
                        <div class="stat-label">Admin Actions Today</div>
                    </div>
                    <div class="stat-card attorney">
                        <div class="stat-number"><?= $auditStats['by_user_type']['attorney'] ?? 0 ?></div>
                        <div class="stat-label">Attorney Actions Today</div>
                    </div>
                    <div class="stat-card employee">
                        <div class="stat-number"><?= $auditStats['by_user_type']['employee'] ?? 0 ?></div>
                        <div class="stat-label">Employee Actions Today</div>
                    </div>
                    <div class="stat-card client">
                        <div class="stat-number"><?= $auditStats['by_user_type']['client'] ?? 0 ?></div>
                        <div class="stat-label">Client Actions Today</div>
                    </div>
                                    <div class="stat-card security">
                    <div class="stat-number"><?= $securityStats['security_events_today'] ?? 0 ?></div>
                    <div class="stat-label">Security Events Today</div>
                    <div class="stat-details">
                        <small>
                            <?= $securityStats['critical_events_today'] ?? 0 ?> Critical | 
                            <?= $securityStats['blocked_attempts_today'] ?? 0 ?> Blocked | 
                            <?= $securityStats['failed_logins_today'] ?? 0 ?> Failed Logins
                        </small>
                    </div>
                </div>
                </div>

                <!-- Filters Section -->
                <div class="filters-section">
                    <h3><i class="fas fa-filter"></i> Filter Audit Trail</h3>
                    <form method="GET" action="">
                        <div class="filters-grid">
                            <div class="filter-group">
                                <label for="user_type">User Type</label>
                                <select name="user_type" id="user_type">
                                    <option value="all" <?= $userType === 'all' ? 'selected' : '' ?>>All User Types</option>
                                    <option value="admin" <?= $userType === 'admin' ? 'selected' : '' ?>>Admin</option>
                                    <option value="attorney" <?= $userType === 'attorney' ? 'selected' : '' ?>>Attorney</option>
                                    <option value="employee" <?= $userType === 'employee' ? 'selected' : '' ?>>Employee</option>
                                    <option value="client" <?= $userType === 'client' ? 'selected' : '' ?>>Client</option>
                                </select>
                            </div>
                            
                            <div class="filter-group">
                                <label for="module">Module</label>
                                <select name="module" id="module">
                                    <option value="all" <?= $module === 'all' ? 'selected' : '' ?>>All Modules</option>
                                    <?php foreach ($modules as $mod): ?>
                                        <option value="<?= htmlspecialchars($mod) ?>" <?= $module === $mod ? 'selected' : '' ?>>
                                            <?= htmlspecialchars($mod) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            
                            <div class="filter-group">
                                <label for="status">Status</label>
                                <select name="status" id="status">
                                    <option value="all" <?= $status === 'all' ? 'selected' : '' ?>>All Status</option>
                                    <option value="success" <?= $status === 'success' ? 'selected' : '' ?>>Success</option>
                                    <option value="failed" <?= $status === 'failed' ? 'selected' : '' ?>>Failed</option>
                                    <option value="warning" <?= $status === 'warning' ? 'selected' : '' ?>>Warning</option>
                                </select>
                            </div>
                            
                            <div class="filter-group">
                                <label for="date_from">Date From</label>
                                <input type="date" name="date_from" id="date_from" value="<?= htmlspecialchars($dateFrom) ?>">
                            </div>
                            
                            <div class="filter-group">
                                <label for="date_to">Date To</label>
                                <input type="date" name="date_to" id="date_to" value="<?= htmlspecialchars($dateTo) ?>">
                            </div>
                            
                            <div class="filter-group">
                                <label for="search">Search</label>
                                <input type="text" name="search" id="search" placeholder="Search actions, users, descriptions..." value="<?= htmlspecialchars($search) ?>">
                            </div>
                        </div>
                        
                        <div class="filter-actions">
                            <button type="submit" class="btn-filter">
                                <i class="fas fa-search"></i> Apply Filters
                            </button>
                            <a href="admin_audit.php" class="btn-reset">
                                <i class="fas fa-times"></i> Reset Filters
                            </a>
                        </div>
                    </form>
                </div>

                <!-- Audit Trail Table -->
                <div class="audit-table-container">
                    <div class="table-header">
                        <h3 class="table-title">
                            <i class="fas fa-list"></i> 
                            Audit Trail Log 
                            <span style="font-size: 1rem; color: #6c757d; font-weight: normal;">
                                (<?= $totalRecords ?> total records, showing <?= count($auditData) ?> on page <?= $page ?> of <?= $totalPages ?>)
                            </span>
                        </h3>
                        <div class="table-actions">
                            <button class="btn-export" onclick="exportAuditTrail()">
                                <i class="fas fa-download"></i> Export CSV
                            </button>
                        </div>
                    </div>

                    <?php if (empty($auditData)): ?>
                        <div class="no-data">
                            <i class="fas fa-search"></i>
                            <h3>No audit records found</h3>
                            <p>Try adjusting your filters or check back later for new activity.</p>
                        </div>
                    <?php else: ?>
                        <table class="audit-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Module</th>
                                    <th>Description</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($auditData as $record): ?>
                                    <tr>
                                        <td class="timestamp">
                                            <i class="fas fa-clock"></i>
                                            <?= date('M d, Y', strtotime($record['timestamp'])) ?>
                                            <span style="margin: 0 4px;">•</span>
                                            <?= date('h:i A', strtotime($record['timestamp'])) ?>
                                        </td>
                                        <td>
                                            <div class="user-info">
                                                <div>
                                                    <span class="user-type-badge <?= $record['user_type'] ?>">
                                                        <?= ucfirst($record['user_type']) ?>
                                                    </span>
                                                    <strong><?= htmlspecialchars($record['user_name']) ?></strong>
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <strong><?= htmlspecialchars($record['action']) ?></strong>
                                        </td>
                                        <td>
                                            <span class="module-badge"><?= htmlspecialchars($record['module']) ?></span>
                                        </td>
                                        <td>
                                            <?= htmlspecialchars($record['description']) ?>
                                        </td>
                                        <td>
                                            <span class="status-badge status-<?= $record['status'] ?>">
                                                <?= ucfirst($record['status']) ?>
                                            </span>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        
                        <!-- Pagination Controls -->
                        <?php if ($totalPages > 1): ?>
                        <div class="pagination-container">
                            <div class="pagination-info">
                                <span>Page <?= $page ?> of <?= $totalPages ?> (<?= $totalRecords ?> total records)</span>
                            </div>
                            <div class="pagination-controls">
                                <!-- First Page -->
                                <?php if ($page > 1): ?>
                                    <a href="?<?= http_build_query(array_merge($_GET, ['page' => 1])) ?>" class="pagination-btn pagination-first">
                                        <i class="fas fa-angle-double-left"></i> First
                                    </a>
                                <?php else: ?>
                                    <span class="pagination-btn pagination-disabled">
                                        <i class="fas fa-angle-double-left"></i> First
                                    </span>
                                <?php endif; ?>
                                
                                <!-- Previous Page -->
                                <?php if ($page > 1): ?>
                                    <a href="?<?= http_build_query(array_merge($_GET, ['page' => $page - 1])) ?>" class="pagination-btn pagination-prev">
                                        <i class="fas fa-angle-left"></i> Previous
                                    </a>
                                <?php else: ?>
                                    <span class="pagination-btn pagination-disabled">
                                        <i class="fas fa-angle-left"></i> Previous
                                    </span>
                                <?php endif; ?>
                                
                                <!-- Page Numbers -->
                                <div class="pagination-numbers">
                                    <?php
                                    $startPage = max(1, $page - 2);
                                    $endPage = min($totalPages, $page + 2);
                                    
                                    for ($i = $startPage; $i <= $endPage; $i++):
                                    ?>
                                        <?php if ($i == $page): ?>
                                            <span class="pagination-btn pagination-current"><?= $i ?></span>
                                        <?php else: ?>
                                            <a href="?<?= http_build_query(array_merge($_GET, ['page' => $i])) ?>" class="pagination-btn pagination-number"><?= $i ?></a>
                                        <?php endif; ?>
                                    <?php endfor; ?>
                                </div>
                                
                                <!-- Next Page -->
                                <?php if ($page < $totalPages): ?>
                                    <a href="?<?= http_build_query(array_merge($_GET, ['page' => $page + 1])) ?>" class="pagination-btn pagination-next">
                                        Next <i class="fas fa-angle-right"></i>
                                    </a>
                                <?php else: ?>
                                    <span class="pagination-btn pagination-disabled">
                                        Next <i class="fas fa-angle-right"></i>
                                    </span>
                                <?php endif; ?>
                                
                                <!-- Last Page -->
                                <?php if ($page < $totalPages): ?>
                                    <a href="?<?= http_build_query(array_merge($_GET, ['page' => $totalPages])) ?>" class="pagination-btn pagination-last">
                                        Last <i class="fas fa-angle-double-right"></i>
                                    </a>
                                <?php else: ?>
                                    <span class="pagination-btn pagination-disabled">
                                        Last <i class="fas fa-angle-double-right"></i>
                                    </span>
                                <?php endif; ?>
                            </div>
                        </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        const sidebarElement = document.getElementById('adminSidebar');
        const sidebarOverlayElement = document.getElementById('sidebarOverlay');
        const mobileNavToggle = document.getElementById('mobileNavToggle');
        const sidebarLinks = document.querySelectorAll('.sidebar-menu a');
        const sidebarCloseButtons = document.querySelectorAll('.sidebar-close-btn');
        const headerElement = document.querySelector('.header');

        if (headerElement && mobileNavToggle && !headerElement.contains(mobileNavToggle)) {
            headerElement.insertBefore(mobileNavToggle, headerElement.firstChild);
        }

        function setSidebarState(open) {
            const isMobile = window.innerWidth <= 1024;
            const effectiveOpen = open && isMobile;

            document.body.classList.toggle('sidebar-open', effectiveOpen);

            if (sidebarElement) {
                sidebarElement.setAttribute('aria-hidden', effectiveOpen ? 'false' : (isMobile ? 'true' : 'false'));
            }

            if (sidebarOverlayElement) {
                sidebarOverlayElement.classList.toggle('visible', effectiveOpen);
            }

            if (mobileNavToggle) {
                mobileNavToggle.setAttribute('aria-expanded', effectiveOpen ? 'true' : 'false');
                const iconEl = mobileNavToggle.querySelector('i');
                if (iconEl) {
                    iconEl.className = effectiveOpen ? 'fas fa-times' : 'fas fa-bars';
                }
            }
        }

        if (mobileNavToggle && sidebarElement) {
            mobileNavToggle.addEventListener('click', () => {
                const isOpen = document.body.classList.contains('sidebar-open') && window.innerWidth <= 1024;
                setSidebarState(!isOpen);
            });
        }

        if (sidebarOverlayElement) {
            sidebarOverlayElement.addEventListener('click', () => setSidebarState(false));
        }

        sidebarCloseButtons.forEach(btn => btn.addEventListener('click', () => setSidebarState(false)));

        sidebarLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth <= 1024) {
                    setSidebarState(false);
                }
            });
        });

        window.addEventListener('resize', () => {
            if (window.innerWidth > 1024) {
                setSidebarState(false);
            }
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && document.body.classList.contains('sidebar-open')) {
                setSidebarState(false);
            }
        });

        setSidebarState(false);
    </script>

    <script>
        function exportAuditTrail() {
            // Get current filters (excluding page parameter for full export)
            const urlParams = new URLSearchParams(window.location.search);
            urlParams.delete('page'); // Remove page parameter to export all records
            const exportUrl = 'export_audit_trail.php?' + urlParams.toString();
            
            // Create temporary link and trigger download
            const link = document.createElement('a');
            link.href = exportUrl;
            link.download = 'audit_trail_' + new Date().toISOString().split('T')[0] + '.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }


        function showSetupInstructions() {
            alert('To set up the audit trail system:\n\n1. Go to phpMyAdmin\n2. Select your "lawfirm" database\n3. Click on "Import"\n4. Choose the updated "lawfirm.sql" file\n5. Click "Go" to import\n\nThis will create the audit_trail table and sample data.');
        }

        // Auto-refresh disabled - user can manually refresh if needed
        // setInterval(function() {
        //     // Only refresh if no filters are applied
        //     const urlParams = new URLSearchParams(window.location.search);
        //     if (urlParams.toString() === '') {
        //         location.reload();
        //     }
        // }, 30000);
</script>
    <script src="assets/js/unread-messages.js?v=<?= time() ?>"></script>
</body>
</html> 