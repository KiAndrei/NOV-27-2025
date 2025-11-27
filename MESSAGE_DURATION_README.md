# Message Duration & Archive System

## Overview
This system automatically archives messages to local files after a specified duration and removes them from the database. Messages remain visible on the website even after being deleted from the database by reading from archived files.

## Features
- **Automatic Archiving**: Messages older than the configured duration are automatically archived to local JSON files
- **Seamless Display**: Archived messages are still visible on the website
- **Visual Indicators**: Archived messages are marked with an archive icon (📦) in the UI
- **Database Cleanup**: Expired messages are removed from the database to save space

## Configuration

### Message Duration
The default message duration is **7 days**. To change this, edit `message_archive_helper.php`:

```php
private $messageDurationDays = 7; // Change this value
```

Or modify it programmatically:
```php
$archiveHelper = new MessageArchiveHelper();
$archiveHelper->setMessageDuration(14); // 14 days
```

## Archive Location
Archived messages are stored in:
```
/messages_archive/
```

Files are named: `conversation_{conversation_id}_{message_type}.json`

## Running the Cleanup Script

### Manual Execution
Run the cleanup script manually:
```bash
php cleanup_expired_messages.php
```

### Automated Execution (Cron)
Set up a cron job to run the cleanup automatically. For example, to run daily at 2 AM:

**Linux/Mac:**
```bash
0 2 * * * cd /path/to/your/project && php cleanup_expired_messages.php >> /var/log/message_cleanup.log 2>&1
```

**Windows (Task Scheduler):**
1. Open Task Scheduler
2. Create a new task
3. Set trigger to daily at 2 AM
4. Set action to run: `php.exe C:\xampp\htdocs\NOV-25-2025\cleanup_expired_messages.php`

## How It Works

1. **Message Storage**: New messages are stored in the database as usual
2. **Archive Process**: When messages exceed the duration:
   - Messages are read from the database
   - Saved to JSON files in `messages_archive/` directory
   - Deleted from the database
3. **Message Display**: When fetching messages:
   - System reads from both database and archive files
   - Combines and sorts all messages chronologically
   - Displays them in the UI with archive indicators

## Visual Indicators

- **Archived Messages**: Display with:
  - Archive icon (📦) in the message metadata
  - Slightly reduced opacity (85%)
  - Italic text style

## Files Modified

- `message_archive_helper.php` - Core archiving functionality
- `cleanup_expired_messages.php` - Cleanup script
- `admin_messages.php` - Updated to read from archive
- `attorney_messages.php` - Updated to read from archive
- `employee_messages.php` - Updated to read from archive
- `client_messages.php` - Updated to read from archive

## Notes

- Archive files are stored permanently unless manually deleted
- The system preserves all message data including sender, timestamp, and content
- Archived messages maintain their original `sent_at` timestamp for proper sorting
- The cleanup script is safe to run multiple times (idempotent)

