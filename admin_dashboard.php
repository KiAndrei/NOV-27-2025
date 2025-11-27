<?php
session_start();
if (!isset($_SESSION['admin_name']) || $_SESSION['user_type'] !== 'admin') {
    header('Location: login_form.php');
    exit();
}

// Set cache control headers to prevent back button access after logout
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

require_once 'config.php';

// Total cases
$total_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases")->fetch_row()[0];
// Total documents
$total_documents = $conn->query("SELECT COUNT(*) FROM attorney_documents WHERE is_deleted = 0")->fetch_row()[0] + $conn->query("SELECT COUNT(*) FROM employee_documents WHERE is_deleted = 0")->fetch_row()[0];
// Total users
$total_users = $conn->query("SELECT COUNT(*) FROM user_form")->fetch_row()[0];
// Upcoming hearings (next 7 days)
$today = date('Y-m-d');
$next_week = date('Y-m-d', strtotime('+7 days'));
$upcoming_hearings = $conn->query("SELECT COUNT(*) FROM case_schedules WHERE date BETWEEN '$today' AND '$next_week'")->fetch_row()[0];

// Additional statistics for comprehensive dashboard
// Active cases
$active_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases WHERE status = 'Active'")->fetch_row()[0];
// Completed cases
$completed_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases WHERE status = 'Completed'")->fetch_row()[0];
// Pending cases
$pending_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases WHERE status = 'Pending'")->fetch_row()[0];
// Total attorneys
$total_attorneys = $conn->query("SELECT COUNT(*) FROM user_form WHERE user_type = 'attorney'")->fetch_row()[0];
// Total employees
$total_employees = $conn->query("SELECT COUNT(*) FROM user_form WHERE user_type = 'employee'")->fetch_row()[0];
// Total clients
$total_clients = $conn->query("SELECT COUNT(*) FROM user_form WHERE user_type = 'client'")->fetch_row()[0];
// Today's appointments
$today_appointments = $conn->query("SELECT COUNT(*) FROM case_schedules WHERE date = '$today'")->fetch_row()[0];
// This month's cases
$this_month = date('Y-m');
$this_month_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases WHERE DATE_FORMAT(created_at, '%Y-%m') = '$this_month'")->fetch_row()[0];
// This month's documents
$this_month_documents = $conn->query("SELECT COUNT(*) FROM attorney_documents WHERE is_deleted = 0 AND DATE_FORMAT(upload_date, '%Y-%m') = '$this_month'")->fetch_row()[0] + $conn->query("SELECT COUNT(*) FROM employee_documents WHERE is_deleted = 0 AND DATE_FORMAT(upload_date, '%Y-%m') = '$this_month'")->fetch_row()[0];
// This month's new users
$this_month_users = $conn->query("SELECT COUNT(*) FROM user_form WHERE DATE_FORMAT(created_at, '%Y-%m') = '$this_month'")->fetch_row()[0];
// This month's new appointments/schedules
$this_month_appointments = $conn->query("SELECT COUNT(*) FROM case_schedules WHERE DATE_FORMAT(date, '%Y-%m') = '$this_month'")->fetch_row()[0];
// This month's pending cases (new pending this month)
$this_month_pending_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases WHERE status = 'Pending' AND DATE_FORMAT(created_at, '%Y-%m') = '$this_month'")->fetch_row()[0];
// System storage usage (approximate)
$storage_usage = $conn->query("SELECT SUM(file_size) FROM attorney_documents WHERE is_deleted = 0")->fetch_row()[0] + $conn->query("SELECT SUM(file_size) FROM employee_documents WHERE is_deleted = 0")->fetch_row()[0];
$storage_mb = round(($storage_usage ?? 0) / 1024 / 1024, 2);

// eFiling Statistics - All submissions from all attorneys
$total_efilings = 0;
$successful_efilings = 0;
$failed_efilings = 0;
$this_month_efilings = 0;
$today_efilings = 0;

// Total eFiling submissions (all attorneys)
$total_efilings = $conn->query("SELECT COUNT(*) FROM efiling_history")->fetch_row()[0];

// Successful eFiling submissions (all attorneys)
$successful_efilings = $conn->query("SELECT COUNT(*) FROM efiling_history WHERE status='Sent'")->fetch_row()[0];

// Failed eFiling submissions (all attorneys)
$failed_efilings = $conn->query("SELECT COUNT(*) FROM efiling_history WHERE status='Failed'")->fetch_row()[0];

// This month's eFiling submissions (all attorneys)
$this_month_efilings = $conn->query("SELECT COUNT(*) FROM efiling_history WHERE DATE_FORMAT(created_at, '%Y-%m') = '$this_month'")->fetch_row()[0];

// Today's eFiling submissions (all attorneys)
$today_efilings = $conn->query("SELECT COUNT(*) FROM efiling_history WHERE DATE(created_at) = '$today'")->fetch_row()[0];

// Case status distribution - Ensure we always have data
$status_counts = [];
$res = $conn->query("SELECT status, COUNT(*) as cnt FROM attorney_cases GROUP BY status");
while ($row = $res->fetch_assoc()) {
    $status_counts[$row['status'] ?? 'Unknown'] = (int)$row['cnt'];
}

// If no cases exist, show default statuses with sample data
if (empty($status_counts)) {
    $status_counts = [
        'Active' => 4,
        'Pending' => 3,
        'Closed' => 2
    ];
}

// Recent activities - Enhanced with more data
$recent_activities = [];

// Recent cases
$res = $conn->query("SELECT 'case' as type, title, created_at, status FROM attorney_cases ORDER BY created_at DESC LIMIT 4");
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Case', 'title' => $row['title'], 'date' => $row['created_at'], 'status' => $row['status']];
}

// Recent documents
$res = $conn->query("SELECT 'document' as type, file_name, upload_date, category FROM attorney_documents WHERE is_deleted = 0 ORDER BY upload_date DESC LIMIT 3");
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Document', 'title' => $row['file_name'], 'date' => $row['upload_date'], 'category' => $row['category']];
}

$res = $conn->query("SELECT 'document' as type, file_name, upload_date, category FROM employee_documents WHERE is_deleted = 0 ORDER BY upload_date DESC LIMIT 3");
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Document', 'title' => $row['file_name'], 'date' => $row['upload_date'], 'category' => $row['category']];
}

// Recent user registrations
$res = $conn->query("SELECT 'user' as type, name, created_at, user_type FROM user_form ORDER BY created_at DESC LIMIT 3");
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'User', 'title' => $row['name'], 'date' => $row['created_at'], 'user_type' => $row['user_type']];
}

// Recent schedules
$res = $conn->query("SELECT 'schedule' as type, title, date, start_time FROM case_schedules ORDER BY date DESC, start_time DESC LIMIT 3");
while ($row = $res->fetch_assoc()) {
    $recent_activities[] = ['type' => 'Schedule', 'title' => $row['title'], 'date' => $row['date'] . ' ' . $row['start_time']];
}

// Sort by date
usort($recent_activities, function($a, $b) {
    return strtotime($b['date']) - strtotime($a['date']);
});

$recent_activities = array_slice($recent_activities, 0, 8);

// Upcoming schedules for today and tomorrow
$upcoming_schedules = [];
$tomorrow = date('Y-m-d', strtotime('+1 day'));
$res = $conn->query("SELECT cs.*, uf.name as client_name, ac.title as case_title, 
                    uf_attorney.name as attorney_name FROM case_schedules cs 
                    LEFT JOIN user_form uf ON cs.client_id = uf.id 
                    LEFT JOIN attorney_cases ac ON cs.case_id = ac.id 
                    LEFT JOIN user_form uf_attorney ON cs.attorney_id = uf_attorney.id 
                    WHERE cs.date BETWEEN '$today' AND '$tomorrow' 
                    ORDER BY cs.date, cs.start_time LIMIT 5");
while ($row = $res->fetch_assoc()) {
    $upcoming_schedules[] = $row;
}

// Top performing attorneys (by case count)
$top_attorneys = [];
$res = $conn->query("SELECT uf.name, COUNT(ac.id) as case_count FROM user_form uf 
                    LEFT JOIN attorney_cases ac ON uf.id = ac.attorney_id 
                    WHERE uf.user_type = 'attorney' 
                    GROUP BY uf.id, uf.name 
                    ORDER BY case_count DESC LIMIT 5");
while ($row = $res->fetch_assoc()) {
    $top_attorneys[] = $row;
}

// Monthly case trends
$monthly_cases = array_fill(1, 12, 0);
$year = date('Y');
$stmt = $conn->prepare("SELECT MONTH(created_at) as month, COUNT(*) as cnt FROM attorney_cases WHERE YEAR(created_at) = ? GROUP BY month");
$stmt->bind_param("i", $year);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $monthly_cases[(int)$row['month']] = (int)$row['cnt'];
}

// If no cases exist, show sample monthly data with more realistic distribution
if ($total_cases == 0) {
    $monthly_cases = [2, 3, 1, 4, 2, 3, 1, 2, 3, 1, 2, 1];
}

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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?= time() ?>">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="assets/js/unread-messages.js?v=<?= time() ?>"></script>
</head>
<body>
    <div class="sidebar" id="adminSidebar">
        <div class="sidebar-header">
            <img src="images/logo.jpg" alt="Logo">
            <h2>Opiña Law Office</h2>
        </div>
        <button class="sidebar-close-btn" type="button" aria-label="Close sidebar">
            <i class="fas fa-times"></i>
        </button>
        <ul class="sidebar-menu">
            <li><a href="admin_dashboard.php" class="active"><i class="fas fa-home"></i><span>Dashboard</span></a></li>
            <li><a href="admin_managecases.php"><i class="fas fa-gavel"></i><span>Case Management</span></a></li>
            <li><a href="admin_documents.php"><i class="fas fa-file-alt"></i><span>Document Storage</span></a></li>
            <li><a href="admin_schedule.php"><i class="fas fa-calendar-alt"></i><span>Scheduling</span></a></li>
            <li><a href="admin_audit.php"><i class="fas fa-history"></i><span>Audit Trail</span></a></li>
            <li><a href="admin_efiling.php"><i class="fas fa-paper-plane"></i><span>E-Filing</span></a></li>
            <li><a href="admin_document_generation.php"><i class="fas fa-file-alt"></i><span>Document Generation</span></a></li>
            <li><a href="admin_usermanagement.php"><i class="fas fa-users-cog"></i><span>User Management</span></a></li>
            <li><a href="admin_clients.php"><i class="fas fa-users"></i><span>Client Management</span></a></li>
            <li><a href="admin_messages.php" class="has-badge"><i class="fas fa-comments"></i><span>Messages</span><span class="unread-message-badge hidden" id="unreadMessageBadge">0</span></a></li>
        </ul>
    </div>
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <div class="main-content">
        <?php 
        $page_title = 'Admin Dashboard';
        $page_subtitle = 'Complete overview of system activities and statistics';
        include 'components/profile_header.php'; 
        ?>
        <button class="mobile-nav-toggle" id="mobileNavToggle" aria-label="Toggle navigation" aria-controls="adminSidebar" aria-expanded="false" type="button">
            <i class="fas fa-bars"></i>
        </button>
        
        <!-- Welcome Section -->
        <div class="welcome-section">
            <div class="welcome-content">
                <h2>Welcome back, <?= htmlspecialchars($_SESSION['admin_name']) ?>!</h2>
                <p>Here's what's happening in your law office today</p>
            </div>
            <div class="welcome-time">
                <div class="current-time">
                    <i class="fas fa-clock"></i>
                    <span id="currentDateTime"></span>
                </div>
            </div>
        </div>

        <!-- Statistics Cards -->
        <div class="dashboard-cards">
            <div class="stat-card primary relative">
                <div class="stat-icon">
                        <i class="fas fa-gavel"></i>
                    </div>
                <div class="stat-content">
                    <div class="stat-value"><?= number_format($total_cases) ?></div>
                    <div class="stat-label">Total Cases</div>
                    <div class="stat-details">
                        <span class="stat-detail active"><?= $active_cases ?> Active</span>
                        <span class="stat-detail completed"><?= $completed_cases ?> Completed</span>
                </div>
            </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ +<?= $this_month_cases ?> this month</span>
            </div>
            
            <div class="stat-card success relative">
                <div class="stat-icon">
                        <i class="fas fa-file-alt"></i>
                    </div>
                <div class="stat-content">
                    <div class="stat-value"><?= number_format($total_documents) ?></div>
                    <div class="stat-label">Total Documents</div>
                    <div class="stat-details">
                        <span class="stat-detail"><?= $storage_mb ?> MB stored</span>
                </div>
            </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ +<?= $this_month_documents ?> this month</span>
            </div>
            
            <div class="stat-card info relative">
                <div class="stat-icon">
                        <i class="fas fa-users"></i>
                    </div>
                <div class="stat-content">
                    <div class="stat-value"><?= number_format($total_users) ?></div>
                    <div class="stat-label">Total Users</div>
                    <div class="stat-details">
                        <span class="stat-detail"><?= $total_attorneys ?> Attorneys</span>
                        <span class="stat-detail"><?= $total_employees ?> Employees</span>
                        <span class="stat-detail"><?= $total_clients ?> Clients</span>
                </div>
            </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ +<?= $this_month_users ?> this month</span>
            </div>
            
            <div class="stat-card warning relative">
                <div class="stat-icon">
                        <i class="fas fa-calendar-check"></i>
                    </div>
                <div class="stat-content">
                    <div class="stat-value"><?= number_format($upcoming_hearings) ?></div>
                    <div class="stat-label">Upcoming Hearings</div>
                    <div class="stat-details">
                        <span class="stat-detail"><?= $today_appointments ?> Today</span>
                        <span class="stat-detail"><?= max(0, $upcoming_hearings - $today_appointments) ?> Next 7 days</span>
                </div>
                </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ +<?= $this_month_appointments ?> this month</span>
            </div>
        </div>

        <!-- Additional Statistics Row -->
        <div class="dashboard-cards secondary">
            <div class="stat-card secondary relative">
                <div class="stat-icon">
                    <i class="fas fa-chart-line"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value"><?= $this_month_cases ?></div>
                    <div class="stat-label">Cases This Month</div>
                    <div class="stat-details">
                        <span class="stat-detail"><?= date('F Y') ?></span>
                    </div>
                </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ Active month trend</span>
            </div>
            
            <div class="stat-card secondary relative">
                <div class="stat-icon">
                    <i class="fas fa-hourglass-half"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value"><?= $pending_cases ?></div>
                    <div class="stat-label">Pending Cases</div>
                    <div class="stat-details">
                        <span class="stat-detail">Awaiting action</span>
                    </div>
                </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ +<?= $this_month_pending_cases ?> this month</span>
            </div>
            
            <div class="stat-card secondary relative">
                <div class="stat-icon">
                    <i class="fas fa-calendar-day"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value"><?= $today_appointments ?></div>
                    <div class="stat-label">Today's Appointments</div>
                    <div class="stat-details">
                        <span class="stat-detail"><?= date('M j, Y') ?></span>
                    </div>
                </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ +<?= $this_month_appointments ?> this month</span>
            </div>
            
            <div class="stat-card efiling relative">
                <div class="stat-icon">
                    <i class="fas fa-paper-plane"></i>
                </div>
                <div class="stat-content">
                    <div class="stat-value"><?= number_format($total_efilings) ?></div>
                    <div class="stat-label">Total eFilings</div>
                    <div class="stat-details">
                        <span class="stat-detail"><?= number_format($successful_efilings) ?> sent</span>
                        <?php if ($failed_efilings > 0): ?>
                            <span class="stat-detail failed"><?= number_format($failed_efilings) ?> failed</span>
                        <?php endif; ?>
                    </div>
                </div>
                <span class="absolute top-3 right-4 text-green-600 text-sm font-medium">↑ +<?= $this_month_efilings ?> this month</span>
            </div>
        </div>

        <!-- Analytics Section -->
        <div class="analytics-section">
            <div class="section-header">
                <h2><i class="fas fa-chart-bar"></i> Analytics & Reports</h2>
                <p>Visual insights into your law office performance</p>
            </div>
            <div class="charts-grid">
                <div class="chart-card">
                    <div class="chart-header">
                <h3><i class="fas fa-chart-pie"></i> Case Status Distribution</h3>
                        <div class="chart-actions">
                            <button class="chart-btn" onclick="exportChart('caseStatusChart')">
                                <i class="fas fa-download"></i>
                            </button>
                        </div>
                    </div>
                <div class="chart-container">
                    <canvas id="caseStatusChart"></canvas>
                    <?php if ($total_cases == 0): ?>
                    <div class="chart-sample-notice" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: rgba(255,255,255,0.9); padding: 10px; border-radius: 5px; font-size: 12px; color: #666; text-align: center; pointer-events: none;">
                        <i class="fas fa-info-circle"></i> Sample data shown
                    </div>
                    <?php endif; ?>
                </div>
            </div>
                
                <div class="chart-card">
                    <div class="chart-header">
                <h3><i class="fas fa-chart-line"></i> Monthly Case Trends (<?= $year ?>)</h3>
                        <div class="chart-actions">
                            <button class="chart-btn" onclick="exportChart('monthlyTrendsChart')">
                                <i class="fas fa-download"></i>
                            </button>
                        </div>
                    </div>
                <div class="chart-container">
                    <canvas id="monthlyTrendsChart"></canvas>
                    <?php if ($total_cases == 0): ?>
                    <div class="chart-sample-notice" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: rgba(255,255,255,0.9); padding: 10px; border-radius: 5px; font-size: 12px; color: #666; text-align: center; pointer-events: none;">
                        <i class="fas fa-info-circle"></i> Sample data shown
                    </div>
                    <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Activity & Schedule Section -->
        <div class="activity-schedule-section">
            <div class="section-header">
                <h2><i class="fas fa-calendar-check"></i> Today's Overview</h2>
                <p>Current activities and upcoming schedules</p>
            </div>
            <div class="activity-schedule-grid">
        <!-- Recent Activities -->
                <div class="activities-card">
                    <div class="card-header">
            <h3><i class="fas fa-clock"></i> Recent Activities</h3>
                        <a href="admin_audit.php" class="view-all-btn">View All</a>
                    </div>
                    <div class="activities-list">
                <?php if (count($recent_activities) > 0): ?>
                    <?php foreach ($recent_activities as $activity): ?>
                                <div class="activity-item">
                                    <div class="activity-icon">
                                        <i class="fas fa-<?= 
                                            strtolower($activity['type']) === 'case' ? 'gavel' : 
                                            (strtolower($activity['type']) === 'document' ? 'file-alt' : 
                                            (strtolower($activity['type']) === 'user' ? 'user-plus' : 
                                            (strtolower($activity['type']) === 'schedule' ? 'calendar' : 'info-circle'))) 
                                        ?>"></i>
                            </div>
                                    <div class="activity-content">
                                        <div class="activity-title"><?= htmlspecialchars($activity['title']) ?></div>
                                        <div class="activity-meta">
                                            <span class="activity-type"><?= ucfirst($activity['type']) ?></span>
                                            <?php if (isset($activity['status'])): ?>
                                                <span class="activity-status status-<?= strtolower($activity['status']) ?>"><?= $activity['status'] ?></span>
                                            <?php endif; ?>
                                            <?php if (isset($activity['category'])): ?>
                                                <span class="activity-category"><?= $activity['category'] ?></span>
                                            <?php endif; ?>
                                            <?php if (isset($activity['user_type'])): ?>
                                                <span class="activity-user-type"><?= ucfirst($activity['user_type']) ?></span>
                                            <?php endif; ?>
                                </div>
                                        <div class="activity-time"><?= date('M j, Y g:i A', strtotime($activity['date'])) ?></div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                            <div class="empty-state">
                                <i class="fas fa-inbox"></i>
                        <p>No recent activities</p>
                    </div>
                <?php endif; ?>
            </div>
                </div>

                <!-- Upcoming Schedules -->
                <div class="schedules-card">
                    <div class="card-header">
                        <h3><i class="fas fa-calendar-alt"></i> Upcoming Schedules</h3>
                        <a href="admin_schedule.php" class="view-all-btn">View All</a>
                    </div>
                    <div class="schedules-list">
                        <?php if (count($upcoming_schedules) > 0): ?>
                            <?php foreach ($upcoming_schedules as $schedule): ?>
                                <div class="schedule-item">
                                    <div class="schedule-date">
                                        <div class="date-day"><?= date('j', strtotime($schedule['date'])) ?></div>
                                        <div class="date-month"><?= date('M', strtotime($schedule['date'])) ?></div>
                                    </div>
                                    <div class="schedule-content">
                                        <div class="schedule-title"><?= htmlspecialchars($schedule['title']) ?></div>
                                        <div class="schedule-meta">
                                            <span class="schedule-time">
                                                <i class="fas fa-clock"></i>
                                                <?= date('g:i A', strtotime($schedule['start_time'])) ?>
                                            </span>
                                            <span class="schedule-type"><?= $schedule['type'] ?></span>
                                        </div>
                                        <?php if ($schedule['attorney_name']): ?>
                                            <div class="schedule-attorney">
                                                <i class="fas fa-user-tie"></i>
                                                <?= htmlspecialchars($schedule['attorney_name']) ?>
                                            </div>
                                        <?php endif; ?>
                                        <?php if ($schedule['case_title']): ?>
                                            <div class="schedule-case">
                                                <i class="fas fa-gavel"></i>
                                                <?= htmlspecialchars($schedule['case_title']) ?>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="empty-state">
                                <i class="fas fa-calendar-times"></i>
                                <p>No upcoming schedules</p>
                            </div>
                        <?php endif; ?>
        </div>
    </div>

            </div>
        </div>

        <!-- Team Performance Section -->
        <div class="team-performance-section">
            <div class="section-header">
                <h2><i class="fas fa-users"></i> Team Performance</h2>
                <p>Track your team's productivity and achievements</p>
            </div>
            <div class="team-performance-grid">
                <!-- Top Attorneys -->
                <div class="attorneys-card">
                    <div class="card-header">
                        <h3><i class="fas fa-trophy"></i> Top Attorneys</h3>
                        <a href="admin_usermanagement.php" class="view-all-btn">View All</a>
                    </div>
                    <div class="attorneys-list">
                        <?php if (count($top_attorneys) > 0): ?>
                            <?php foreach ($top_attorneys as $index => $attorney): ?>
                                <div class="attorney-item">
                                    <div class="attorney-rank"><?= $index + 1 ?></div>
                                    <div class="attorney-avatar">
                                        <i class="fas fa-user-tie"></i>
                                    </div>
                                    <div class="attorney-content">
                                        <div class="attorney-name"><?= htmlspecialchars($attorney['name']) ?></div>
                                        <div class="attorney-cases"><?= $attorney['case_count'] ?> cases</div>
                                    </div>
                                    <div class="attorney-badge">
                                        <i class="fas fa-medal"></i>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="empty-state">
                                <i class="fas fa-user-tie"></i>
                                <p>No attorney data available</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Quick Stats Summary -->
                <div class="quick-stats-card">
                    <div class="card-header">
                        <h3><i class="fas fa-tachometer-alt"></i> Quick Stats</h3>
                    </div>
                    <div class="quick-stats-list">
                        <div class="quick-stat-item">
                            <div class="quick-stat-icon">
                                <i class="fas fa-gavel"></i>
                            </div>
                            <div class="quick-stat-content">
                                <div class="quick-stat-value"><?= $active_cases ?></div>
                                <div class="quick-stat-label">Active Cases</div>
                            </div>
                        </div>
                        <div class="quick-stat-item">
                            <div class="quick-stat-icon">
                                <i class="fas fa-calendar-day"></i>
                            </div>
                            <div class="quick-stat-content">
                                <div class="quick-stat-value"><?= $today_appointments ?></div>
                                <div class="quick-stat-label">Today's Appointments</div>
                            </div>
                        </div>
                        <div class="quick-stat-item">
                            <div class="quick-stat-icon">
                                <i class="fas fa-file-alt"></i>
                            </div>
                            <div class="quick-stat-content">
                                <div class="quick-stat-value"><?= $this_month_cases ?></div>
                                <div class="quick-stat-label">Cases This Month</div>
                            </div>
                        </div>
                        <div class="quick-stat-item">
                            <div class="quick-stat-icon">
                                <i class="fas fa-users"></i>
                            </div>
                            <div class="quick-stat-content">
                                <div class="quick-stat-value"><?= $total_attorneys ?></div>
                                <div class="quick-stat-label">Active Attorneys</div>
                            </div>
                        </div>
                        <div class="quick-stat-item">
                            <div class="quick-stat-icon">
                                <i class="fas fa-paper-plane"></i>
                            </div>
                            <div class="quick-stat-content">
                                <div class="quick-stat-value"><?= $today_efilings ?></div>
                                <div class="quick-stat-label">Today's eFilings</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <style>
        /* Modern Admin Dashboard Styles */
        .welcome-section {
            background: linear-gradient(135deg, #5D0E26 0%, #8B1538 100%);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 32px;
            color: white;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 8px 32px rgba(93, 14, 38, 0.3);
        }

        .welcome-content {
            flex: 1;
        }

        .welcome-content h2 {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 8px;
            font-family: 'Playfair Display', serif;
        }

        .welcome-content p {
            font-size: 1.1rem;
            opacity: 0.9;
            margin-bottom: 0;
        }

        .welcome-time {
            display: flex;
            align-items: center;
            justify-content: flex-end;
        }

        .current-time {
            background: rgba(255, 255, 255, 0.1);
            padding: 12px 20px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 1rem;
            opacity: 0.9;
        }

        .sidebar {
            transition: transform 0.3s ease;
        }

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

        .mobile-nav-toggle span {
            letter-spacing: 0.3px;
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

        body.sidebar-open {
            overflow: hidden;
        }

        @media (max-width: 1200px) {
            .dashboard-cards,
            .dashboard-cards.secondary {
                grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
            }
        }

        @media (max-width: 1024px) {
            body {
                flex-direction: column;
                align-items: stretch;
            }

        .sidebar {
            transform: translateX(-100%);
            width: 260px !important;
            max-width: 80%;
            box-shadow: 12px 0 30px rgba(0, 0, 0, 0.25);
        }

            body.sidebar-open .sidebar {
                transform: translateX(0);
            }

            .main-content {
                margin-left: 0 !important;
                max-width: 100% !important;
                padding: 18px 18px 28px;
            }

            .mobile-nav-toggle {
                display: inline-flex;
            }
            .sidebar-close-btn {
                display: flex;
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
            }

            .header .user-info {
                margin-left: auto;
                align-items: center !important;
                gap: 12px !important;
            }

            .analytics-section,
            .activity-schedule-section,
            .team-performance-section {
                padding: 20px;
                margin-bottom: 16px;
            }
        }

        @media (max-width: 768px) {
            .mobile-nav-toggle {
                position: absolute;
                left: 16px;
                top: 16px;
                width: auto;
                justify-content: center;
            }

            .welcome-section {
                padding: 26px;
            }

            .header .user-details {
                display: none !important;
            }

            .header .user-info {
                justify-content: flex-end;
            }

            .header-title {
                text-align: center;
                width: 100%;
            }

            .header-title h1 {
                width: 100%;
                text-align: center;
            }

            .header-title p {
                display: none;
            }

            .analytics-section,
            .activity-schedule-section,
            .team-performance-section {
                padding: 18px;
            }
        }

        @media (max-width: 600px) {
            .welcome-section {
                padding: 22px;
            }
        }


        /* Compact Dashboard Cards - Override all external styles */
        .dashboard-cards,
        body .dashboard-cards,
        .main-content .dashboard-cards {
            display: grid !important;
            grid-template-columns: repeat(4, 1fr) !important;
            gap: 10px !important;
            margin-bottom: 15px !important;
        }

        .dashboard-cards.secondary,
        body .dashboard-cards.secondary,
        .main-content .dashboard-cards.secondary {
            grid-template-columns: repeat(4, 1fr) !important;
            gap: 10px !important;
            margin-bottom: 15px !important;
        }

        /* Clean card design - balanced layout */
        .stat-card,
        body .stat-card,
        .main-content .stat-card {
            background: white !important;
            border-radius: 10px !important;
            padding: 14px 16px !important;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.08) !important;
            border: 1px solid #e9ecef !important;
            border-top: 2px solid #5D0E26 !important;
            transition: all 0.2s ease !important;
            position: relative !important;
            overflow: hidden !important;
            height: 130px !important;
            display: flex !important;
            flex-direction: row !important;
            align-items: center !important;
            gap: 12px !important;
            margin: 0 !important;
        }

        /* Subtle corner accent - toned down */
        .stat-card::before,
        body .stat-card::before {
            content: '' !important;
            position: absolute !important;
            top: 0 !important;
            right: 0 !important;
            width: 50px !important;
            height: 50px !important;
            background: linear-gradient(135deg, rgba(93, 14, 38, 0.03) 0%, transparent 100%) !important;
            border-radius: 0 10px 0 50px !important;
            pointer-events: none !important;
        }

        .stat-card::after,
        body .stat-card::after {
            display: none !important;
        }

        .stat-card:hover,
        body .stat-card:hover {
            transform: translateY(-1px) !important;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.12) !important;
            border-top-color: #8B1538 !important;
        }

        /* Icon - balanced size */
        .stat-icon,
        body .stat-icon {
            width: 36px !important;
            height: 36px !important;
            border-radius: 7px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            color: white !important;
            font-size: 0.9rem !important;
            flex-shrink: 0 !important;
            margin: 0 !important;
            box-shadow: 0 2px 4px rgba(93, 14, 38, 0.2) !important;
            position: relative !important;
            z-index: 1 !important;
        }

        .stat-card.primary .stat-icon,
        body .stat-card.primary .stat-icon { background: linear-gradient(135deg, #5D0E26, #8B1538) !important; }
        .stat-card.success .stat-icon,
        body .stat-card.success .stat-icon { background: linear-gradient(135deg, #5D0E26, #8B1538) !important; }
        .stat-card.info .stat-icon,
        body .stat-card.info .stat-icon { background: linear-gradient(135deg, #5D0E26, #8B1538) !important; }
        .stat-card.warning .stat-icon,
        body .stat-card.warning .stat-icon { background: linear-gradient(135deg, #5D0E26, #8B1538) !important; }
        .stat-card.secondary .stat-icon,
        body .stat-card.secondary .stat-icon { background: linear-gradient(135deg, #5D0E26, #8B1538) !important; }
        .stat-card.efiling .stat-icon,
        body .stat-card.efiling .stat-icon { background: linear-gradient(135deg, #5D0E26, #8B1538) !important; }

        /* Content area - flex column, takes remaining space */
        .stat-content,
        body .stat-content {
            flex: 1 !important;
            min-width: 0 !important;
            display: flex !important;
            flex-direction: column !important;
            justify-content: center !important;
            gap: 3px !important;
            position: relative !important;
            z-index: 1 !important;
        }

        /* Value - balanced size */
        .stat-value,
        body .stat-value {
            font-size: 1.6rem !important;
            font-weight: 700 !important;
            color: #1a1a1a !important;
            margin: 0 !important;
            line-height: 1 !important;
            padding: 0 !important;
            letter-spacing: -0.3px !important;
        }

        /* Enhanced label with better styling */
        .stat-label,
        body .stat-label {
            font-size: 1rem !important; /* Increased from 0.7rem to 1rem (16px) */
            color: #666 !important;
            margin: 0 !important;
            font-weight: 600 !important;
            text-transform: uppercase !important;
            letter-spacing: 0.5px !important;
            padding: 0 !important;
            line-height: 1.2 !important;
        }

        /* Details - clean styling with proper alignment */
        .stat-details,
        body .stat-details {
            display: flex !important;
            flex-wrap: wrap !important;
            gap: 3px !important;
            margin: 3px 0 0 0 !important;
            padding: 0 !important;
            align-items: center !important;
            align-content: flex-start !important;
        }
        /* Force Upcoming Hearings badges inline */
        .stat-card.warning .stat-details {
            flex-wrap: nowrap !important;
            gap: 6px !important;
        }
        .stat-card.warning .stat-detail { margin-right: 0 !important; }

        .stat-detail,
        body .stat-detail {
            background: #f0f2f5 !important;
            padding: 2px 5px !important;
            border-radius: 3px !important;
            font-size: 0.58rem !important;
            color: #555 !important;
            line-height: 1.2 !important;
            margin: 0 !important;
            font-weight: 500 !important;
            display: inline-flex !important;
            align-items: center !important;
            white-space: nowrap !important;
        }

        .stat-detail.active,
        body .stat-detail.active { background: #d4edda !important; color: #155724 !important; }
        .stat-detail.completed,
        body .stat-detail.completed { background: #cce5ff !important; color: #004085 !important; }
        .stat-detail.failed,
        body .stat-detail.failed { background: #f8d7da !important; color: #721c24 !important; }

        /* Trend indicator - subtle */
        .stat-trend,
        body .stat-trend {
            display: inline-flex !important;
            align-items: center !important;
            gap: 3px !important;
            font-size: 0.58rem !important;
            color: #27ae60 !important;
            font-weight: 500 !important;
            margin-left: 4px !important;
            padding: 0 !important;
        }

        .stat-trend i,
        body .stat-trend i {
            font-size: 0.6rem !important;
        }

        /* Tailwind utility classes for consistent green badge labels */
        .relative,
        body .relative {
            position: relative !important;
        }

        .absolute,
        body .absolute {
            position: absolute !important;
        }

        .top-3,
        body .top-3 {
            top: 0.75rem !important; /* 12px */
        }

        .right-4,
        body .right-4 {
            right: 1rem !important; /* 16px */
        }

        .text-green-600,
        body .text-green-600 {
            color: #16a34a !important;
        }

        .text-sm,
        body .text-sm {
            font-size: 0.875rem !important; /* 14px */
            line-height: 1.25rem !important;
        }

        .font-medium,
        body .font-medium {
            font-weight: 500 !important;
        }

        /* Green badge labels - top-right corner positioning */
        .stat-card .absolute.top-3.right-4,
        body .stat-card .absolute.top-3.right-4,
        .stat-card.relative .absolute,
        body .stat-card.relative .absolute {
            position: absolute !important;
            top: 0.75rem !important;
            right: 1rem !important;
            z-index: 10 !important;
            white-space: nowrap !important;
            color: #16a34a !important;
            font-size: 0.875rem !important;
            line-height: 1.25rem !important;
            font-weight: 500 !important;
            margin: 0 !important;
            padding: 0 !important;
        }

        .analytics-section, .activity-schedule-section, .team-performance-section {
            width: 100%;
            display: block;
            margin-bottom: 20px;
            background: #800000;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25);
            padding: 24px;
        }

        .section-header {
            margin-bottom: 24px;
            text-align: center;
        }

        .section-header h2 {
            font-size: 1.8rem;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
        }

        .section-header p {
            color: #e0e0e0;
            font-size: 1rem;
        }

        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        .activity-schedule-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        .team-performance-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        .quick-stats-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .quick-stats-list {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .quick-stat-item {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 16px;
            background: #f8f9fa;
            border-radius: 12px;
            transition: all 0.3s ease;
        }

        .quick-stat-item:hover {
            background: #e9ecef;
            transform: translateX(4px);
        }

        .quick-stat-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.2rem;
        }

        .quick-stat-content {
            flex: 1;
        }

        .quick-stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: #333;
            margin-bottom: 4px;
        }

        .quick-stat-label {
            font-size: 0.9rem;
            color: #666;
        }

        .charts-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }

        .chart-card, .activities-card, .schedules-card, .attorneys-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
            overflow: hidden;
        }

        .chart-header, .card-header {
            padding: 20px 24px;
            border-bottom: 1px solid #f0f0f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .chart-header h3, .card-header h3 {
            font-size: 1.1rem;
            font-weight: 600;
            color: #333;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .chart-actions {
            display: flex;
            gap: 8px;
        }

        .chart-btn {
            width: 32px;
            height: 32px;
            border: none;
            background: #f8f9fa;
            border-radius: 6px;
            color: #666;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .chart-btn:hover {
            background: #5D0E26;
            color: white;
        }

        .view-all-btn {
            color: #5D0E26;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            transition: color 0.2s ease;
        }

        .view-all-btn:hover {
            color: #8B1538;
        }

        .chart-container {
            padding: 24px;
            height: 300px;
        }

        .activities-list, .schedules-list, .attorneys-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .activity-item, .schedule-item, .attorney-item {
            padding: 16px 24px;
            border-bottom: 1px solid #f0f0f0;
            transition: background 0.2s ease;
        }

        .activity-item:hover, .schedule-item:hover, .attorney-item:hover {
            background: #f8f9fa;
        }

        .activity-item {
            display: flex;
            align-items: flex-start;
            gap: 16px;
        }

        .activity-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.9rem;
            flex-shrink: 0;
        }

        .activity-content {
            flex: 1;
        }

        .activity-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 4px;
            line-height: 1.3;
        }

        .activity-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 4px;
        }

        .activity-type, .activity-category, .activity-user-type {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            color: #666;
        }

        .activity-status {
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 500;
        }

        .status-active { background: #d4edda; color: #155724; }
        .status-completed { background: #cce5ff; color: #004085; }
        .status-pending { background: #fff3cd; color: #856404; }

        .activity-time {
            font-size: 0.8rem;
            color: #999;
        }

        .schedule-item {
            display: flex;
            gap: 16px;
        }

        .schedule-date {
            text-align: center;
            flex-shrink: 0;
        }

        .date-day {
            font-size: 1.5rem;
            font-weight: 700;
            color: #5D0E26;
            line-height: 1;
        }

        .date-month {
            font-size: 0.8rem;
            color: #666;
            text-transform: uppercase;
        }

        .schedule-content {
            flex: 1;
        }

        .schedule-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 4px;
        }

        .schedule-meta {
            display: flex;
            gap: 12px;
            margin-bottom: 4px;
        }

        .schedule-time, .schedule-type {
            font-size: 0.8rem;
            color: #666;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .schedule-attorney, .schedule-case {
            font-size: 0.8rem;
            color: #999;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .schedule-attorney {
            color: #5D0E26;
            font-weight: 600;
        }

        .schedule-attorney i {
            color: #8B1538;
        }

        .attorney-item {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .attorney-rank {
            width: 24px;
            height: 24px;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .attorney-avatar {
            width: 40px;
            height: 40px;
            background: #f8f9fa;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #666;
        }

        .attorney-content {
            flex: 1;
        }

        .attorney-name {
            font-weight: 600;
            color: #333;
            margin-bottom: 2px;
        }

        .attorney-cases {
            font-size: 0.8rem;
            color: #666;
        }

        .attorney-badge {
            color: #f39c12;
        }


        .empty-state {
            text-align: center;
            padding: 40px 24px;
            color: rgba(255, 255, 255, 0.8);
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 16px;
            opacity: 0.5;
            color: rgba(255, 255, 255, 0.6);
        }

        .empty-state p {
            color: rgba(255, 255, 255, 0.8);
        }

        /* Ensure sections stay stacked vertically on all screen sizes */
        .analytics-section, .activity-schedule-section, .team-performance-section {
            display: block !important;
            width: 100% !important;
            margin-bottom: 20px !important;
        }

        /* Responsive Design */
        @media (max-width: 1200px) {
            .charts-grid, .activity-schedule-grid, .team-performance-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 768px) {
            .welcome-section {
                flex-direction: column;
                text-align: center;
                gap: 24px;
            }
            
            .welcome-time {
                justify-content: center;
            }
            
            .dashboard-cards,
            body .dashboard-cards,
            .main-content .dashboard-cards {
                grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
                gap: 16px !important;
            }
            
            .dashboard-cards.secondary,
            body .dashboard-cards.secondary,
            .main-content .dashboard-cards.secondary {
                grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
            }

            .stat-card,
            body .stat-card,
            .main-content .stat-card {
                height: auto !important;
                min-height: 160px !important;
                flex-direction: column !important;
                align-items: flex-start !important;
                padding: 16px !important;
            }
            
        }

        @media (max-width: 480px) {
            .dashboard-cards,
            body .dashboard-cards,
            .main-content .dashboard-cards {
                grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
                gap: 12px !important;
            }
            
            .dashboard-cards.secondary,
            body .dashboard-cards.secondary,
            .main-content .dashboard-cards.secondary {
                grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
            }

            .stat-card,
            body .stat-card,
            .main-content .stat-card {
                min-height: 150px !important;
                padding: 14px !important;
            }

            .stat-details,
            body .stat-details {
                flex-direction: column !important;
                align-items: flex-start !important;
                gap: 4px !important;
            }
        }
    </style>

    <script>
        const sidebarElement = document.querySelector('.sidebar');
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

            if (effectiveOpen) {
                document.body.classList.add('sidebar-open');
            } else {
                document.body.classList.remove('sidebar-open');
            }

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

        sidebarCloseButtons.forEach(btn => {
            btn.addEventListener('click', () => setSidebarState(false));
        });

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

        // Update current date and time
        function updateDateTime() {
            const now = new Date();
            const options = { 
                weekday: 'long', 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            };
            document.getElementById('currentDateTime').textContent = now.toLocaleDateString('en-US', options);
        }

        // Update time every minute
        updateDateTime();
        setInterval(updateDateTime, 60000);

        // Chart export function
        function exportChart(chartId) {
            const canvas = document.getElementById(chartId);
            const url = canvas.toDataURL('image/png');
            const link = document.createElement('a');
            link.download = chartId + '.png';
            link.href = url;
            link.click();
        }

        // Case Status Chart
        const ctx = document.getElementById('caseStatusChart').getContext('2d');
        const caseStatusData = {
            labels: <?= json_encode(array_keys($status_counts)) ?>,
            datasets: [{
                data: <?= json_encode(array_values($status_counts)) ?>,
                backgroundColor: [
                    '#28a745', '#ffc107', '#6c757d', '#17a2b8', '#dc3545', '#6f42c1', '#fd7e14', '#20c997'
                ],
                borderWidth: 3,
                borderColor: '#fff',
                hoverBorderWidth: 4
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
                                size: 12,
                                family: 'Poppins'
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleFont: {
                            family: 'Poppins'
                        },
                        bodyFont: {
                            family: 'Poppins'
                        },
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                },
                elements: {
                    arc: {
                        borderWidth: 3
                    }
                },
                cutout: '60%'
            }
        });

        // Monthly Trends Chart
        const ctx2 = document.getElementById('monthlyTrendsChart').getContext('2d');
        const monthlyData = {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            datasets: [{
                label: 'Cases Created',
                data: <?= json_encode(array_values($monthly_cases)) ?>,
                backgroundColor: 'rgba(93, 14, 38, 0.1)',
                borderColor: '#5D0E26',
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#5D0E26',
                pointBorderColor: '#fff',
                pointBorderWidth: 3,
                pointRadius: 6,
                pointHoverRadius: 8
            }]
        };
        
        const monthlyTrendsChart = new Chart(ctx2, {
            type: 'line',
            data: monthlyData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        titleFont: {
                            family: 'Poppins'
                        },
                        bodyFont: {
                            family: 'Poppins'
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        stepSize: 1,
                        max: function(context) {
                            const max = Math.max(...context.chart.data.datasets[0].data);
                            return max > 0 ? Math.ceil(max * 1.2) : 5; // Add 20% padding, minimum 5
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.1)'
                        },
                        ticks: {
                            font: {
                                family: 'Poppins'
                            },
                            stepSize: 1
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(0,0,0,0.1)'
                        },
                        ticks: {
                            font: {
                                family: 'Poppins'
                            }
                        }
                    }
                },
                elements: {
                    point: {
                        hoverRadius: 8
                    }
                }
            }
        });

        // Fix chart responsiveness on window resize
        window.addEventListener('resize', function() {
            caseStatusChart.resize();
            monthlyTrendsChart.resize();
        });

        // Force chart resize after page load
        setTimeout(function() {
            caseStatusChart.resize();
            monthlyTrendsChart.resize();
        }, 100);

        // Add smooth scrolling for better UX
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    </script>
</body>
</html> 