# Request Access Flow Test

## Test Scenario: Client submits request from client_documents.php

### Step 1: Initial State
- Client visits `client_documents.php`
- No existing request in database
- `$show_request_access = true` (because no request_status)
- Shows "Request Access" modal/page

### Step 2: Form Submission
**POST Data:**
```
action: submit_request
full_name: John Doe
street_address: 123 Main St
barangay: Barangay 1
city: Manila
province: Metro Manila
zip_code: 1000
sex: Male
concern_description: Need legal documents
valid_id_front: [FILE]
valid_id_back: [FILE]
privacy_consent: on
```

### Step 3: POST Handler Processing
1. ✅ Validates all fields
2. ✅ Uploads front ID to `uploads/client/valid_id_front_{client_id}_{timestamp}.{ext}`
3. ✅ Uploads back ID to `uploads/client/valid_id_back_{client_id}_{timestamp}.{ext}`
4. ✅ Generates request_id: `REQ-YYYYMMDD-####-####`
5. ✅ Inserts to database: `client_request_form` table
6. ✅ Logs audit trail
7. ✅ Notifies all employees
8. ✅ Redirects to: `client_documents.php?submitted=1`

### Step 4: After Redirect
- Queries database again
- Finds request with status = "Pending"
- `$show_request_access = true` (because status !== 'Approved')
- `$can_submit_request = false` (because status === 'Pending')
- Shows "Request Under Review" message
- Button changes to "Request Pending Review" (disabled)

### Step 5: Employee Reviews
- Employee opens `employee_request_management.php`
- Sees pending request
- Reviews and approves

### Step 6: After Approval
- Client visits `client_documents.php` again
- Queries database: status = "Approved"
- `$show_request_access = false` (because status === 'Approved')
- Shows document generation page (with documentStatusContainer)

## Expected Database Insert

```sql
INSERT INTO client_request_form (
    request_id, 
    client_id, 
    full_name, 
    address, 
    sex, 
    concern_description, 
    valid_id_front_path, 
    valid_id_front_filename, 
    valid_id_back_path, 
    valid_id_back_filename, 
    privacy_consent
) VALUES (
    'REQ-20251029-0001-1234',
    1,
    'John Doe',
    '123 Main St, Barangay 1, Manila, Metro Manila 1000',
    'Male',
    'Need legal documents',
    'uploads/client/valid_id_front_1_1730188800.jpg',
    'valid_id_front_1_1730188800.jpg',
    'uploads/client/valid_id_back_1_1730188800.jpg',
    'valid_id_back_1_1730188800.jpg',
    1
)
```

## Potential Issues to Check

### ✅ Fixed Issues:
1. ✅ JavaScript error when container doesn't exist - FIXED with check
2. ✅ POST handler missing in client_documents.php - ADDED
3. ✅ Error message display - ADDED to both files

### ⚠️ Things to Verify:
1. **Database table exists** - Check if `client_request_form` table has all required columns
2. **Upload directory** - Check if `uploads/client/` directory is writable
3. **Session variable** - Check if `$_SESSION['client_name']` is set
4. **Audit logger** - Check if `audit_logger.php` and `$auditLogger` work properly
5. **Notifications table** - Check if `notifications` table exists

## Testing Commands

```bash
# Check if upload directory exists and is writable
ls -la uploads/client/

# Check PHP error log
tail -f xampp/php/logs/php_error_log

# Test form submission (manual test in browser)
1. Login as client
2. Go to client_documents.php
3. Click "Request Access"
4. Fill form with valid data
5. Upload 2 valid IDs (JPG/PNG/PDF)
6. Check privacy consent
7. Submit
8. Check for:
   - Redirect to client_documents.php?submitted=1
   - Button changes to "Request Pending Review"
   - Request appears in employee_request_management.php
```

## Success Criteria

✅ Form submits without errors
✅ Files upload successfully
✅ Database record created
✅ Page redirects properly
✅ Button state changes correctly
✅ Employee receives notification
✅ Request visible in employee panel

## Error Handling Test Cases

1. **Missing front ID**: Should show error "Please upload front ID file."
2. **Missing back ID**: Should show error "Please upload back ID file."
3. **Invalid file type**: Should show error "Invalid file type..."
4. **File too large**: Should show error "...file size exceeds 5MB limit."
5. **No privacy consent**: Should show error "You must agree to the Data Privacy Act..."
6. **Database error**: Should show error "Failed to submit request..." + SQL error

