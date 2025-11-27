<?php
/**
 * Cleanup Expired Messages Script
 * This script should be run periodically (via cron or manually)
 * to archive and delete expired messages from the database
 */

require_once 'config.php';
require_once 'message_archive_helper.php';

// Set execution time limit for large cleanup operations
set_time_limit(300); // 5 minutes

$archiveHelper = new MessageArchiveHelper();

echo "Starting message cleanup...\n";
$durationMinutes = $archiveHelper->getMessageDurationMinutes();
$durationDescription = $durationMinutes >= 60 ? round($durationMinutes / 60 / 24, 4) . " days" : $durationMinutes . " minutes";
$expiredTimestamp = time() - ($durationMinutes * 60);
echo "Message duration: " . $durationDescription . "\n";
echo "Current time: " . date('Y-m-d H:i:s') . "\n";
echo "Expiring messages older than: " . date('Y-m-d H:i:s', $expiredTimestamp) . "\n\n";

try {
    $result = $archiveHelper->cleanupExpiredMessages($conn);
    
    echo "Cleanup completed successfully!\n";
    echo "Messages archived: " . $result['archived'] . "\n";
    echo "Messages deleted from database: " . $result['deleted'] . "\n";
    
} catch (Exception $e) {
    echo "Error during cleanup: " . $e->getMessage() . "\n";
    exit(1);
}

