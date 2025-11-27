<?php
/**
 * Message Archive Helper
 * Handles archiving messages to local files before deletion from database
 */

require_once 'config.php';

class MessageArchiveHelper {
    private $archiveDir;
    private $messageDurationMinutes; // Messages expire after this many minutes
    
    public function __construct() {
        $this->archiveDir = __DIR__ . '/messages_archive';
        
        // Get duration from config or use default
        if (defined('MESSAGE_DURATION_MINUTES')) {
            $this->messageDurationMinutes = MESSAGE_DURATION_MINUTES;
        } elseif (defined('MESSAGE_DURATION_DAYS')) {
            $this->messageDurationMinutes = MESSAGE_DURATION_DAYS * 24 * 60;
        } else {
            $this->messageDurationMinutes = 7 * 24 * 60; // Default: 7 days
        }
        
        // Create archive directory if it doesn't exist
        if (!file_exists($this->archiveDir)) {
            mkdir($this->archiveDir, 0755, true);
        }
    }
    
    /**
     * Get archive file path for a conversation
     */
    private function getArchiveFilePath($conversationId, $messageType) {
        // messageType: 'attorney' or 'employee'
        $filename = "conversation_{$conversationId}_{$messageType}.json";
        return $this->archiveDir . '/' . $filename;
    }
    
    /**
     * Archive messages to local file
     */
    public function archiveMessages($conversationId, $messageType, $messages) {
        $filePath = $this->getArchiveFilePath($conversationId, $messageType);
        
        // Load existing archived messages
        $archivedMessages = [];
        $existingIds = [];
        if (file_exists($filePath)) {
            $existingData = file_get_contents($filePath);
            $archivedMessages = json_decode($existingData, true) ?: [];
            // Track existing message IDs to avoid duplicates
            foreach ($archivedMessages as $archived) {
                if (isset($archived['id'])) {
                    $existingIds[$archived['id']] = true;
                }
            }
        }
        
        // Add new messages to archive (avoid duplicates)
        foreach ($messages as $msg) {
            // Skip if message already exists in archive
            if (isset($msg['id']) && isset($existingIds[$msg['id']])) {
                continue;
            }
            
            // Add archive timestamp
            $msg['archived_at'] = date('Y-m-d H:i:s');
            $archivedMessages[] = $msg;
            
            // Track this ID
            if (isset($msg['id'])) {
                $existingIds[$msg['id']] = true;
            }
        }
        
        // Save to file
        file_put_contents($filePath, json_encode($archivedMessages, JSON_PRETTY_PRINT));
        
        return true;
    }
    
    /**
     * Get archived messages for a conversation
     */
    public function getArchivedMessages($conversationId, $messageType) {
        $filePath = $this->getArchiveFilePath($conversationId, $messageType);
        
        if (!file_exists($filePath)) {
            return [];
        }
        
        $data = file_get_contents($filePath);
        $messages = json_decode($data, true) ?: [];
        
        return $messages;
    }
    
    /**
     * Get all messages (from database + archive) for a conversation
     */
    public function getAllMessages($conversationId, $messageType, $conn) {
        $allMessages = [];
        
        // Get messages from database
        if ($messageType === 'attorney') {
            $stmt = $conn->prepare("SELECT id, sender_id, sender_type, message, sent_at, is_seen FROM client_attorney_messages WHERE conversation_id = ? ORDER BY sent_at ASC");
        } else {
            $stmt = $conn->prepare("SELECT id, sender_id, sender_type, message, sent_at, is_seen FROM client_employee_messages WHERE conversation_id = ? ORDER BY sent_at ASC");
        }
        
        $stmt->bind_param('i', $conversationId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        while ($row = $result->fetch_assoc()) {
            $row['from_archive'] = false;
            // Ensure is_seen is set
            if (!isset($row['is_seen'])) {
                $row['is_seen'] = 0;
            }
            $allMessages[] = $row;
        }
        
        // Get archived messages
        $archivedMessages = $this->getArchivedMessages($conversationId, $messageType);
        foreach ($archivedMessages as $msg) {
            $msg['from_archive'] = true;
            // Ensure is_seen is set for archived messages
            if (!isset($msg['is_seen'])) {
                $msg['is_seen'] = 0;
            }
            $allMessages[] = $msg;
        }
        
        // Sort by sent_at
        usort($allMessages, function($a, $b) {
            $timeA = isset($a['sent_at']) ? strtotime($a['sent_at']) : 0;
            $timeB = isset($b['sent_at']) ? strtotime($b['sent_at']) : 0;
            return $timeA - $timeB;
        });
        
        return $allMessages;
    }
    
    /**
     * Clean up expired messages from database
     * Moves expired messages to archive before deleting
     */
    public function cleanupExpiredMessages($conn) {
        $expiredTimestamp = time() - ($this->messageDurationMinutes * 60);
        $expiredDate = date('Y-m-d H:i:s', $expiredTimestamp);
        $archivedCount = 0;
        $deletedCount = 0;
        
        // Process attorney messages
        $stmt = $conn->prepare("SELECT id, conversation_id, sender_id, sender_type, message, sent_at, is_seen FROM client_attorney_messages WHERE sent_at < ? ORDER BY conversation_id, sent_at");
        $stmt->bind_param('s', $expiredDate);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $messagesByConversation = [];
        while ($row = $result->fetch_assoc()) {
            $convId = $row['conversation_id'];
            if (!isset($messagesByConversation[$convId])) {
                $messagesByConversation[$convId] = [];
            }
            $messagesByConversation[$convId][] = $row;
        }
        
        // Archive and delete attorney messages
        foreach ($messagesByConversation as $convId => $messages) {
            if (count($messages) > 0) {
                $this->archiveMessages($convId, 'attorney', $messages);
                $archivedCount += count($messages);
                
                $ids = array_column($messages, 'id');
                if (count($ids) > 0) {
                    $placeholders = implode(',', array_fill(0, count($ids), '?'));
                    $stmt = $conn->prepare("DELETE FROM client_attorney_messages WHERE id IN ($placeholders)");
                    $types = str_repeat('i', count($ids));
                    $stmt->bind_param($types, ...$ids);
                    $stmt->execute();
                    $deletedCount += $stmt->affected_rows;
                }
            }
        }
        
        // Process employee messages
        $stmt = $conn->prepare("SELECT id, conversation_id, sender_id, sender_type, message, sent_at, is_seen FROM client_employee_messages WHERE sent_at < ? ORDER BY conversation_id, sent_at");
        $stmt->bind_param('s', $expiredDate);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $messagesByConversation = [];
        while ($row = $result->fetch_assoc()) {
            $convId = $row['conversation_id'];
            if (!isset($messagesByConversation[$convId])) {
                $messagesByConversation[$convId] = [];
            }
            $messagesByConversation[$convId][] = $row;
        }
        
        // Archive and delete employee messages
        foreach ($messagesByConversation as $convId => $messages) {
            if (count($messages) > 0) {
                $this->archiveMessages($convId, 'employee', $messages);
                $archivedCount += count($messages);
                
                $ids = array_column($messages, 'id');
                if (count($ids) > 0) {
                    $placeholders = implode(',', array_fill(0, count($ids), '?'));
                    $stmt = $conn->prepare("DELETE FROM client_employee_messages WHERE id IN ($placeholders)");
                    $types = str_repeat('i', count($ids));
                    $stmt->bind_param($types, ...$ids);
                    $stmt->execute();
                    $deletedCount += $stmt->affected_rows;
                }
            }
        }
        
        return [
            'archived' => $archivedCount,
            'deleted' => $deletedCount
        ];
    }
    
    /**
     * Set message duration in days (backwards compatibility)
     */
    public function setMessageDuration($days) {
        $this->setMessageDurationDays($days);
    }
    
    /**
     * Get message duration in days (backwards compatibility)
     */
    public function getMessageDuration() {
        return $this->getMessageDurationDays();
    }
    
    /**
     * Set duration in minutes
     */
    public function setMessageDurationMinutes($minutes) {
        $minutes = max(1, (int)$minutes);
        $this->messageDurationMinutes = $minutes;
    }
    
    /**
     * Set duration in days
     */
    public function setMessageDurationDays($days) {
        $days = max(0.0007, (float)$days); // ~1 minute minimum
        $this->messageDurationMinutes = $days * 24 * 60;
    }
    
    /**
     * Get duration in minutes
     */
    public function getMessageDurationMinutes() {
        return $this->messageDurationMinutes;
    }
    
    /**
     * Get duration in days
     */
    public function getMessageDurationDays() {
        return $this->messageDurationMinutes / 60 / 24;
    }
    
    /**
     * Run automatic cleanup if needed (only once per day)
     * This is called automatically when messages pages are accessed
     */
    public function autoCleanupIfNeeded($conn) {
        $lastCleanupFile = $this->archiveDir . '/last_cleanup.txt';
        $shouldRun = false;
        $now = time();
        $intervalMinutes = defined('MESSAGE_CLEANUP_INTERVAL_MINUTES') ? MESSAGE_CLEANUP_INTERVAL_MINUTES : min(max(1, $this->messageDurationMinutes), 24 * 60);
        $intervalSeconds = max(60, $intervalMinutes * 60); // at least once per minute
        
        if (file_exists($lastCleanupFile)) {
            $lastCleanupTime = strtotime(trim(file_get_contents($lastCleanupFile)));
            if ($lastCleanupTime === false || ($now - $lastCleanupTime) >= $intervalSeconds) {
                $shouldRun = true;
            }
        } else {
            $shouldRun = true;
        }
        
        if ($shouldRun) {
            try {
                $result = $this->cleanupExpiredMessages($conn);
                
                // Update last cleanup time
                file_put_contents($lastCleanupFile, date('Y-m-d H:i:s', $now));
                
                // Log the cleanup (optional)
                $logFile = $this->archiveDir . '/cleanup_log.txt';
                $logEntry = "[" . date('Y-m-d H:i:s') . "] Auto-cleanup: Archived " . $result['archived'] . " messages, Deleted " . $result['deleted'] . " messages\n";
                file_put_contents($logFile, $logEntry, FILE_APPEND);
                
                return $result;
            } catch (Exception $e) {
                // Log error but don't break the page
                error_log("Message cleanup error: " . $e->getMessage());
                return null;
            }
        }
        
        return null;
    }
}

