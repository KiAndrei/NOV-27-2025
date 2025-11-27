<?php
/**
 * Message Cleanup Script
 * This script should be run periodically (via cron job) to:
 * 1. Archive expired messages to local files
 * 2. Delete expired messages from database
 * 
 * Usage:
 * - Via cron: Add to crontab: 0 2 * * * php /path/to/cleanup_messages.php
 * - Via browser: Access cleanup_messages.php directly (for testing)
 */

require_once 'config.php';
require_once 'message_archive_helper.php';

// Set execution time limit for large cleanup operations
set_time_limit(300); // 5 minutes

// Log file for cleanup operations
$logFile = __DIR__ . '/messages_archive/cleanup_log.txt';

function logMessage($message) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] $message\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND);
    echo $logEntry; // Also output to console
}

// Check if running from command line or web
$isCli = php_sapi_name() === 'cli';

if (!$isCli && !isset($_GET['run'])) {
    // If accessed via browser without ?run parameter, show info
    die("
    <h2>Message Cleanup Script</h2>
    <p>This script archives and deletes expired messages from the database.</p>
    <p>To run cleanup, add ?run=1 to the URL or set up a cron job.</p>
    <p><strong>Recommended cron schedule:</strong> Daily at 2 AM</p>
    <p><strong>Cron command:</strong> 0 2 * * * php " . __FILE__ . "</p>
    <p><a href='?run=1'>Run Cleanup Now</a></p>
    ");
}

logMessage("=== Starting Message Cleanup ===");
$durationMinutes = defined('MESSAGE_DURATION_MINUTES') ? MESSAGE_DURATION_MINUTES : (MESSAGE_DURATION_DAYS * 24 * 60);
$durationDescription = $durationMinutes >= 60 ? round($durationMinutes / 60 / 24, 2) . " days" : $durationMinutes . " minutes";
logMessage("Message duration: " . $durationDescription);

try {
    $archiveHelper = new MessageArchiveHelper();
    
    // Run cleanup
    $result = $archiveHelper->cleanupExpiredMessages($conn);
    
    logMessage("Cleanup completed successfully!");
    logMessage("Messages archived: " . $result['archived']);
    logMessage("Messages deleted from database: " . $result['deleted']);
    logMessage("=== Cleanup Finished ===");
    
    if ($isCli) {
        exit(0); // Success
    } else {
        echo "<h2>Cleanup Completed Successfully</h2>";
        echo "<p>Messages archived: " . $result['archived'] . "</p>";
        echo "<p>Messages deleted from database: " . $result['deleted'] . "</p>";
        echo "<p><a href='cleanup_messages.php'>Run Again</a></p>";
    }
    
} catch (Exception $e) {
    $errorMsg = "Error during cleanup: " . $e->getMessage();
    logMessage($errorMsg);
    
    if ($isCli) {
        exit(1); // Error
    } else {
        echo "<h2>Error</h2>";
        echo "<p>$errorMsg</p>";
    }
}

