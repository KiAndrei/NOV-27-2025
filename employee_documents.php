<?php
require_once 'session_manager.php';
validateUserAccess('employee');
require_once 'config.php';
require_once 'audit_logger.php';
require_once 'action_logger_helper.php';

$employee_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT profile_image FROM user_form WHERE id=?");
$stmt->bind_param("i", $employee_id);
$stmt->execute();
$res = $stmt->get_result();
$profile_image = '';
if ($res && $row = $res->fetch_assoc()) {
    $profile_image = $row['profile_image'];
}

// Fetch pending requests count for notification badge
$stmt = $conn->prepare("SELECT COUNT(*) FROM client_request_form WHERE status = 'Pending'");
$stmt->execute();
$pending_requests_count = $stmt->get_result()->fetch_row()[0];

// Check for edit modal error from session
$modal_error = null;
$edit_form_data = null;
if (isset($_SESSION['edit_modal_error'])) {
    $modal_error = $_SESSION['edit_modal_error'];
    if (isset($_SESSION['edit_form_data'])) {
        $edit_form_data = $_SESSION['edit_form_data'];
    }
    // Clear the session variables
    unset($_SESSION['edit_modal_error']);
    unset($_SESSION['edit_form_data']);
}
if (!$profile_image || !file_exists($profile_image)) {
        $profile_image = 'images/default-avatar.jpg';
    }

// Helper functions
function get_current_book_number() {
    return date('n'); // Current month (1-12)
}

function get_next_doc_number($conn, $book_number) {
    $stmt = $conn->prepare("SELECT COALESCE(MAX(doc_number), 0) + 1 FROM employee_documents WHERE book_number = ?");
    $stmt->bind_param("i", $book_number);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result->fetch_row()[0];
}

function log_activity($conn, $doc_id, $action, $user_id, $user_name, $doc_number, $book_number, $file_name) {
    $stmt = $conn->prepare("INSERT INTO employee_document_activity (document_id, action, user_id, user_name, form_number, file_name) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('isisis', $doc_id, $action, $user_id, $user_name, $doc_number, $file_name);
    $stmt->execute();
}

// Function to convert Word file to PDF using PhpOffice/PhpWord + DomPDF
function convertWordToPDF($wordFilePath) {
    require_once __DIR__ . '/vendor/autoload.php';
    
    $pathInfo = pathinfo($wordFilePath);
    $directory = $pathInfo['dirname'];
    $filename = $pathInfo['filename'];
    $extension = strtolower($pathInfo['extension']);
    
    // Only convert .docx files (PhpWord doesn't support old .doc format well)
    if ($extension !== 'docx') {
        return $wordFilePath; // Not a .docx file, return original
    }
    
    $pdfFilePath = $directory . '/' . $filename . '.pdf';
    
    try {
        // Load the Word document
        $phpWord = \PhpOffice\PhpWord\IOFactory::load($wordFilePath);
        
        // Create PDF writer using DomPDF
        \PhpOffice\PhpWord\Settings::setPdfRendererName('DomPDF');
        \PhpOffice\PhpWord\Settings::setPdfRendererPath(__DIR__ . '/vendor/dompdf/dompdf');
        
        // Save as PDF
        $pdfWriter = \PhpOffice\PhpWord\IOFactory::createWriter($phpWord, 'PDF');
        $pdfWriter->save($pdfFilePath);
        
        // Check if PDF was created successfully
        if (file_exists($pdfFilePath) && filesize($pdfFilePath) > 0) {
            // Delete the original Word file
            unlink($wordFilePath);
            return $pdfFilePath;
        }
    } catch (Exception $e) {
        // Conversion failed, keep original file
        error_log("Word to PDF conversion failed: " . $e->getMessage());
    }
    
    // If conversion failed, keep original file
    return $wordFilePath;
}

function truncate_document_name($name, $max_length = 18) {
    // Remove file extension for display since we have icons
    $name_without_ext = pathinfo($name, PATHINFO_FILENAME);
    
    if (strlen($name_without_ext) <= $max_length) {
        return $name_without_ext;
    }
    return substr($name_without_ext, 0, $max_length) . '........';
}

// Handle multiple document upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['documents'])) {
    $uploaded_count = 0;
    $errors = [];
    $validated_files = [];
    
    $current_book = get_current_book_number();
    
    // FIRST PASS: Validate ALL files before uploading ANY
    foreach ($_FILES['documents']['name'] as $key => $filename) {
        if ($_FILES['documents']['error'][$key] === UPLOAD_ERR_OK) {
            // Check if the corresponding form data exists
            if (!isset($_POST['category'][$key])) {
                $errors[] = "Category is required for file: " . $filename;
                continue;
            }
            
            $category = $_POST['category'][$key];
            
            if ($category === 'Notarized Documents') {
                if (!isset($_POST['surnames'][$key]) || !isset($_POST['first_names'][$key]) || !isset($_POST['doc_numbers'][$key]) || !isset($_POST['book_numbers'][$key])) {
                    $errors[] = "Missing form data for Notarized Documents: " . $filename;
                    continue;
                }
            } else if ($category === 'Law Office Files') {
                if (!isset($_POST['document_names'][$key]) || empty(trim($_POST['document_names'][$key]))) {
                    $errors[] = "Document name is required for Law Office Files: " . $filename;
                    continue;
                }
            }
            
            if ($category === 'Notarized Documents') {
                $surname = trim($_POST['surnames'][$key]);
                $first_name = trim($_POST['first_names'][$key]);
                $middle_name = trim($_POST['middle_names'][$key] ?? '');
                $doc_number = intval($_POST['doc_numbers'][$key]);
                $book_number = intval($_POST['book_numbers'][$key]);
                $series = isset($_POST['series'][$key]) ? intval($_POST['series'][$key]) : date('Y');
                $affidavit_type = trim($_POST['affidavit_types'][$key] ?? '');
            } else {
                // Law Office Files - no series field
                $surname = '';
                $first_name = '';
                $middle_name = '';
                $doc_number = 0;
                $book_number = 0;
                $series = 0; // No series for Law Office Files
                $affidavit_type = '';
            }
            
            // Set document name based on category
            if ($category === 'Notarized Documents') {
                $doc_name = $surname . ', ' . $first_name;
                if (!empty($middle_name)) {
                    $doc_name .= ' ' . $middle_name;
                }
            } else {
                $doc_name = trim($_POST['document_names'][$key]);
            }
            
            // Validation based on category
            if ($category === 'Notarized Documents') {
                if (empty($surname) || empty($first_name)) {
                    $errors[] = "Surname and First Name are required for file: " . $filename;
                    continue;
                }
                
                if (empty($affidavit_type)) {
                    $errors[] = "Affidavit Type is required for file: " . $filename;
                    continue;
                }
                
                if ($doc_number <= 0) {
                    $errors[] = "Doc number must be greater than 0 for file: " . $filename;
                    continue;
                }
                
                if ($book_number < 1 || $book_number > 12) {
                    $errors[] = "Book number must be between 1-12 for file: " . $filename;
                    continue;
                }
                
                // Check for duplicate doc number in same book AND same series
                $dupCheck = $conn->prepare("SELECT id FROM employee_documents WHERE doc_number = ? AND book_number = ? AND series = ?");
                $dupCheck->bind_param('iii', $doc_number, $book_number, $series);
                $dupCheck->execute();
                $dupCheck->store_result();
                
                if ($dupCheck->num_rows > 0) {
                    $errors[] = "Doc Number $doc_number already exists in Book $book_number for Series $series for file: " . $filename;
                    continue;
                }
            }
            
            // Check for duplicate doc number in current upload batch (only for Notarized Documents)
            if ($category === 'Notarized Documents') {
                for ($j = 0; $j < $key; $j++) {
                    if (isset($_POST['doc_numbers'][$j]) && isset($_POST['book_numbers'][$j]) && isset($_POST['series'][$j]) && isset($_POST['category'][$j]) && $_POST['category'][$j] === 'Notarized Documents') {
                        $prev_doc_num = intval($_POST['doc_numbers'][$j]);
                        $prev_book_num = intval($_POST['book_numbers'][$j]);
                        $prev_series = intval($_POST['series'][$j]);
                        if ($prev_doc_num == $doc_number && $prev_book_num == $book_number && $prev_series == $series) {
                            $errors[] = "Doc Number $doc_number in Book $book_number for Series $series is duplicated in current upload for file: " . $filename;
                            continue 2;
                        }
                    }
                }
            }
            
            // If we reach here, the file is valid
            $validated_files[$key] = [
                'filename' => $filename,
                'surname' => $surname,
                'first_name' => $first_name,
                'middle_name' => $middle_name,
                'doc_name' => $doc_name,
                'doc_number' => $doc_number,
                'book_number' => $book_number,
                'affidavit_type' => $affidavit_type
            ];
        }
    }
    
    // SECOND PASS: Only upload if ALL files are valid
    if (empty($errors)) {
        foreach ($validated_files as $key => $fileData) {
            $filename = $fileData['filename'];
            $doc_name = $fileData['doc_name'];
            $doc_number = $fileData['doc_number'];
            $book_number = $fileData['book_number'];
            $affidavit_type = $fileData['affidavit_type'];
            
            $fileInfo = pathinfo($filename);
            $extension = isset($fileInfo['extension']) ? '.' . $fileInfo['extension'] : '';
            $safeDocName = preg_replace('/[^A-Za-z0-9 _\-]/', '', $doc_name);
            $fileName = $safeDocName . $extension;
            
            $targetDir = 'uploads/employee/';
            if (!is_dir($targetDir)) {
                mkdir($targetDir, 0777, true);
            }
            
            $targetFile = $targetDir . time() . '_' . $key . '_' . $fileName;
            $file_size = $_FILES['documents']['size'][$key];
            $file_type = $_FILES['documents']['type'][$key];
            
            if (move_uploaded_file($_FILES['documents']['tmp_name'][$key], $targetFile)) {
            // Convert Word files to PDF automatically
            $finalFilePath = convertWordToPDF($targetFile);
            
            $uploadedBy = $_SESSION['user_id'] ?? 1;
            $user_name = $_SESSION['employee_name'] ?? 'Employee';
            $category = $_POST['category'][$key];
                
                $stmt = $conn->prepare("INSERT INTO employee_documents (file_name, file_path, category, uploaded_by, doc_number, book_number, series, file_size, file_type, document_name, affidavit_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->bind_param('sssiiiiisss', $fileName, $finalFilePath, $category, $uploadedBy, $doc_number, $book_number, $series, $file_size, $file_type, $doc_name, $affidavit_type);
                $stmt->execute();
                
                $doc_id = $conn->insert_id;
                
                // log_activity($conn, $doc_id, 'Uploaded', $uploadedBy, $user_name, $doc_number, $book_number, $fileName);
                
                // Log to audit trail
                global $auditLogger;
                $auditLogger->logAction(
                    $uploadedBy,
                    $user_name,
                    'employee',
                    'Document Upload',
                    'Document Management',
                    "Uploaded document: $fileName (Category: $category, Doc #: $doc_number, Book #: $book_number)",
                    'success',
                    'medium'
                );
                
                $uploaded_count++;
            } else {
                $errors[] = "Failed to upload file: " . $filename;
            }
        }
    }
    
            if ($uploaded_count > 0) {
                // Return JSON response for modal handling
                header('Content-Type: application/json');
                echo json_encode([
                    'success' => true,
                    'message' => "Documents uploaded successfully! Total uploaded: $uploaded_count.",
                    'type' => 'success',
                    'count' => $uploaded_count
                ]);
                exit();
            }
            if (!empty($errors)) {
                // Return JSON response for modal handling
                header('Content-Type: application/json');
                echo json_encode([
                    'success' => false,
                    'message' => implode('\n', $errors),
                    'type' => 'error'
                ]);
                exit();
            }
}

// Handle edit
if (isset($_POST['edit_id'])) {
    $edit_id = intval($_POST['edit_id']);
    $new_name = trim($_POST['edit_document_name']);
    $new_doc_number = intval($_POST['edit_doc_number']);
    $new_book_number = intval($_POST['edit_book_number']);
    $new_series = isset($_POST['edit_series']) ? intval($_POST['edit_series']) : date('Y');
    $new_affidavit_type = trim($_POST['edit_affidavit_type']);
    
    $uploadedBy = $_SESSION['user_id'] ?? 1;
    $user_name = $_SESSION['employee_name'] ?? 'Employee';
    
    // Determine current category first
    $catStmt = $conn->prepare("SELECT category, doc_number, book_number, affidavit_type FROM employee_documents WHERE id=?");
    $catStmt->bind_param('i', $edit_id);
    $catStmt->execute();
    $catRes = $catStmt->get_result();
    $current_category = 'Unknown';
    $existing = $catRes ? $catRes->fetch_assoc() : null;
    if ($existing) {
        $current_category = $existing['category'] ?? 'Unknown';
    }

    // Get original file_name to preserve the extension
    $stmt = $conn->prepare("SELECT file_name FROM employee_documents WHERE id=?");
    $stmt->bind_param('i', $edit_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $original_file = $result->fetch_assoc();
    
    // Preserve the extension from the original file_name
    if ($original_file) {
        $original_ext = pathinfo($original_file['file_name'], PATHINFO_EXTENSION);
        if (!empty($original_ext) && !preg_match('/\.' . preg_quote($original_ext, '/') . '$/i', $new_name)) {
            $new_name = $new_name . '.' . $original_ext;
        }
    }
    
    if ($current_category === 'Notarized Documents') {
        // Check for duplicate doc number in same book AND same series only for Notarized
        $dupCheck = $conn->prepare("SELECT id FROM employee_documents WHERE doc_number = ? AND book_number = ? AND series = ? AND id != ?");
        $dupCheck->bind_param('iiii', $new_doc_number, $new_book_number, $new_series, $edit_id);
        $dupCheck->execute();
        $dupCheck->store_result();
        if ($dupCheck->num_rows > 0) {
            $error = 'A document with Doc Number ' . $new_doc_number . ' already exists in Book ' . $new_book_number . ' for Series ' . $new_series . '!';
            $_SESSION['edit_modal_error'] = $error;
            $_SESSION['edit_form_data'] = [
                'id' => $edit_id,
                'name' => $new_name,
                'doc_number' => $new_doc_number,
                'book_number' => $new_book_number,
                'series' => $new_series,
                'affidavit_type' => $new_affidavit_type
            ];
            header('Location: employee_documents.php');
            exit();
        }
        // Proceed update all fields
        $stmt = $conn->prepare("UPDATE employee_documents SET file_name=?, document_name=?, doc_number=?, book_number=?, series=?, affidavit_type=? WHERE id=?");
        $stmt->bind_param('ssiiisi', $new_name, $new_name, $new_doc_number, $new_book_number, $new_series, $new_affidavit_type, $edit_id);
        $stmt->execute();
    } else {
        // Law Office Files: update document name only (no series)
        $stmt = $conn->prepare("UPDATE employee_documents SET file_name=?, document_name=? WHERE id=?");
        $stmt->bind_param('ssi', $new_name, $new_name, $edit_id);
        $stmt->execute();
        // keep numbers for logging
        if ($existing) {
            $new_doc_number = intval($existing['doc_number']);
            $new_book_number = intval($existing['book_number']);
            $new_affidavit_type = $existing['affidavit_type'] ?? '';
        }
    }
        
        // log_activity($conn, $edit_id, 'Edited', $uploadedBy, $user_name, $new_doc_number, $new_book_number, $new_name);
        
        // Log to audit trail
        global $auditLogger;
        $auditLogger->logAction(
            $uploadedBy,
            $user_name,
            'employee',
            'Document Edit',
            'Document Management',
            "Edited document: $new_name (Category: $current_category, Doc #: $new_doc_number, Book #: $new_book_number)",
            'success',
            'medium'
        );
        
        header('Location: employee_documents.php?edit_success=1#documents');
        exit();
    }

// Handle delete
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    $id = intval($_GET['delete']);
    $stmt = $conn->prepare("SELECT file_path, file_name, doc_number, book_number, uploaded_by, category, document_name FROM employee_documents WHERE id=?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $res = $stmt->get_result();
    
    if ($res && $row = $res->fetch_assoc()) {
        $user_name = $_SESSION['employee_name'] ?? 'Employee';
        $user_id = $_SESSION['user_id'] ?? 1;
        
        // log_activity($conn, $id, 'Deleted', $user_id, $user_name, $row['doc_number'], $row['book_number'], $row['file_name']);
        
        // Log to audit trail
        global $auditLogger;
        $auditLogger->logAction(
            $user_id,
            $user_name,
            'employee',
            'Document Delete',
            'Document Management',
            "Deleted document: {$row['document_name']} (Category: {$row['category']}, Doc #: {$row['doc_number']}, Book #: {$row['book_number']})",
            'success',
            'high'
        );
    }
    
    $stmt = $conn->prepare("UPDATE employee_documents SET is_deleted = 1 WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    header('Location: employee_documents.php#documents');
    exit();
}

// Build filter conditions
$where_conditions = [];
$where_params = [];
$where_types = '';


// Doc number filter
$filter_doc_number = isset($_GET['doc_number']) ? $_GET['doc_number'] : '';
if ($filter_doc_number) {
    $where_conditions[] = "doc_number = ?";
    $where_params[] = $filter_doc_number;
    $where_types .= 'i';
}

// Book number filter
$filter_book_number = isset($_GET['book_number']) ? $_GET['book_number'] : '';
if ($filter_book_number) {
    $where_conditions[] = "book_number = ?";
    $where_params[] = $filter_book_number;
    $where_types .= 'i';
}

// Series filter
$filter_series = isset($_GET['series']) ? $_GET['series'] : '';
if ($filter_series) {
    $where_conditions[] = "series = ?";
    $where_params[] = $filter_series;
    $where_types .= 'i';
}

// Name filter
$filter_name = isset($_GET['name']) ? $_GET['name'] : '';
if ($filter_name) {
    $where_conditions[] = "file_name LIKE ?";
    $where_params[] = '%' . $filter_name . '%';
    $where_types .= 's';
}



$where_clause = '';
if (!empty($where_conditions)) {
    $where_clause = 'WHERE ' . implode(' AND ', $where_conditions);
}

// Fetch documents with uploader name
$documents = [];
// Ensure soft-deleted documents are excluded
if ($where_clause) {
    $query = "SELECT ed.*, uf.name as uploader_name, uf.user_type FROM employee_documents ed LEFT JOIN user_form uf ON ed.uploaded_by = uf.id $where_clause AND ed.is_deleted = 0 ORDER BY ed.book_number DESC, ed.doc_number ASC";
} else {
    $query = "SELECT ed.*, uf.name as uploader_name, uf.user_type FROM employee_documents ed LEFT JOIN user_form uf ON ed.uploaded_by = uf.id WHERE ed.is_deleted = 0 ORDER BY ed.book_number DESC, ed.doc_number ASC";
}
$stmt = $conn->prepare($query);

if (!empty($where_params)) {
    $stmt->bind_param($where_types, ...$where_params);
}

$stmt->execute();
$result = $stmt->get_result();

if ($result && $result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $documents[] = $row;
    }
}

// Fetch distinct series values for filter dropdown
$available_series = [];
$seriesRes = $conn->query("SELECT DISTINCT CAST(series AS UNSIGNED) as series FROM employee_documents WHERE series IS NOT NULL AND series > 0 ORDER BY series DESC");
if ($seriesRes && $seriesRes->num_rows > 0) {
    while ($row = $seriesRes->fetch_assoc()) {
        $available_series[] = $row['series'];
    }
}

// Fetch recent activity
$activity = [];
$actRes = $conn->query("SELECT * FROM employee_document_activity ORDER BY timestamp DESC LIMIT 10");
if ($actRes && $actRes->num_rows > 0) {
    while ($row = $actRes->fetch_assoc()) {
        $activity[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Document Storage - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?= time() ?>">
    <style>
        /* Profile Modal Override - Ensure consistent compact modal */
        .modal#editProfileModal .modal-content {
            max-height: none !important;
            height: auto !important;
            min-height: auto !important;
            overflow-y: visible !important;
            overflow-x: visible !important;
            margin: 2% auto !important;
            width: 98% !important;
            max-width: 800px !important;
        }
        
        .modal#passwordVerificationModal .modal-content {
            max-height: none !important;
            height: auto !important;
            min-height: auto !important;
            overflow-y: visible !important;
            overflow-x: visible !important;
            margin: 2% auto !important;
            width: 98% !important;
            max-width: 800px !important;
        }
        
        .modal#editProfileModal .modal-body {
            max-height: none !important;
            height: auto !important;
            min-height: auto !important;
            overflow-y: visible !important;
            overflow-x: visible !important;
            padding: 12px !important;
        }
        
        .modal#passwordVerificationModal .modal-body {
            max-height: none !important;
            height: auto !important;
            min-height: auto !important;
            overflow-y: visible !important;
            overflow-x: visible !important;
            padding: 12px !important;
        }
        
        /* Compact modal elements */
        .modal#editProfileModal .form-section {
            margin-bottom: 6px !important;
            padding: 0 !important;
        }
        
        .modal#editProfileModal .form-group {
            margin-bottom: 4px !important;
        }
        
        .modal#editProfileModal .modal-header h2 {
            font-size: 1.1rem !important;
            padding: 8px 12px !important;
        }
        
        .modal#editProfileModal .modal-header {
            padding: 8px 12px !important;
        }
        
        .modal#editProfileModal .form-section h3 {
            font-size: 0.9rem !important;
            margin-bottom: 6px !important;
            padding-bottom: 2px !important;
        }
        
        .modal#editProfileModal .form-group label {
            font-size: 0.75rem !important;
            margin-bottom: 2px !important;
        }
        
        .modal#editProfileModal .form-group input {
            padding: 4px 6px !important;
            font-size: 0.8rem !important;
            border-radius: 4px !important;
        }
        
        .modal#editProfileModal .upload-btn {
            padding: 4px 8px !important;
            font-size: 0.7rem !important;
        }
        
        .modal#editProfileModal .upload-hint {
            font-size: 0.65rem !important;
        }
        
        .modal#editProfileModal .current-profile-image {
            width: 50px !important;
            height: 50px !important;
        }
        
        .modal#editProfileModal .form-actions button {
            padding: 4px 8px !important;
            font-size: 0.75rem !important;
        }
        
        .modal#editProfileModal small {
            font-size: 0.6rem !important;
        }

        .category-tabs {
            display: flex;
            margin-bottom: 0;
            gap: 12px;
            background: white;
            padding: 20px;
            border-radius: 0;
            box-shadow: none;
        }
        
        .tab-btn {
            background: #f8f9fa;
            border: 1px solid #e5e7eb;
            padding: 12px 20px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            color: #6b7280;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
            border-radius: 8px;
            flex: 1;
            justify-content: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .tab-btn:hover {
            background: #e9ecef;
            color: #495057;
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        }
        
        .tab-btn.active {
            background: #5D0E26;
            color: white;
            border-color: #5D0E26;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(93, 14, 38, 0.3);
        }
        
        .tab-btn.active:hover {
            background: #4A0B1E;
            transform: translateY(-1px);
        }
        
        .tab-btn i {
            font-size: 1rem;
        }

        /* Unified Controls Section */
        .unified-controls-section {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
            border: 1px solid #e5e7eb;
        }

        .unified-controls-section .filters-section {
            background: #f8f9fa;
            padding: 20px;
            border-top: 1px solid #e5e7eb;
        }

        .unified-controls-section .filters-section h3 {
            margin: 0 0 15px 0;
            font-size: 1rem;
            font-weight: 600;
            color: #374151;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .unified-controls-section .filters-section h3 i {
            color: #5D0E26;
        }

        /* Upload Modal Styles */
        .upload-modal {
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(2px);
        }

        .upload-modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 0;
            border-radius: 12px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            animation: modalSlideIn 0.3s ease-out;
        }

        @keyframes modalSlideIn {
            from {
                opacity: 0;
                transform: translateY(-50px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .upload-modal-header {
            background: linear-gradient(135deg, #5D0E26, #7A1A3A);
            color: white;
            padding: 20px;
            border-radius: 12px 12px 0 0;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .upload-modal-header.error {
            background: linear-gradient(135deg, #dc3545, #c82333);
        }

        .upload-modal-header.success {
            background: linear-gradient(135deg, #28a745, #1e7e34);
        }

        .upload-modal-header i {
            font-size: 1.5rem;
        }

        .upload-modal-header h3 {
            margin: 0;
            font-size: 1.2rem;
            font-weight: 600;
        }

        .upload-modal-body {
            padding: 25px;
            color: #374151;
            line-height: 1.6;
        }

        .upload-modal-body p {
            margin: 0 0 15px 0;
            font-size: 1rem;
        }

        .upload-modal-footer {
            padding: 20px 25px;
            border-top: 1px solid #e5e7eb;
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }

        .upload-modal-btn {
            padding: 10px 24px;
            border: none;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 80px;
        }

        .upload-modal-btn-primary {
            background: linear-gradient(135deg, #5D0E26, #7A1A3A);
            color: white;
        }

        .upload-modal-btn-primary:hover {
            background: linear-gradient(135deg, #4A0B1E, #6B0F2A);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(93, 14, 38, 0.3);
        }

        .upload-modal-btn-secondary {
            background: #f8f9fa;
            color: #6b7280;
            border: 1px solid #e5e7eb;
        }

        .upload-modal-btn-secondary:hover {
            background: #e9ecef;
            color: #495057;
        }

        .error-highlight {
            border: 2px solid #dc3545 !important;
            box-shadow: 0 0 0 0.2rem rgba(220, 53, 69, 0.25) !important;
        }
        
        /* Download Modal Styles */
        .download-modal {
            max-width: 850px !important;
            max-height: 85vh;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 25px 15px 25px;
            border-bottom: 2px solid #e5e7eb;
            background: #f8fafc;
            margin: -10px -25px 20px -25px;
        }
        
        .modal-header h2 {
            margin: 0;
            color: white !important;
            font-size: 1.4rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .close-btn {
            background: #dc2626;
            color: white;
            border: none;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            transition: all 0.3s ease;
            position: relative;
            right: 0;
            margin: 0;
            flex-shrink: 0;
        }
        
        .close-btn:hover {
            background: #b91c1c;
            transform: scale(1.1);
        }
        
        .date-filter-section {
            margin-bottom: 20px;
            padding: 15px;
            background: #f9fafb;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
        }
        
        .filter-tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-btn {
            background: white;
            border: 1px solid #d1d5db;
            padding: 6px 10px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 500;
            color: #6b7280;
            transition: all 0.3s ease;
            white-space: nowrap;
        }
        
        .filter-btn:hover {
            border-color: #5D0E26;
            color: #5D0E26;
        }
        
        .filter-btn.active {
            background: #5D0E26;
            color: white;
            border-color: #5D0E26;
        }
        
        .custom-date-range {
            display: none !important;
            gap: 10px;
            align-items: center;
            margin-left: 10px;
        }
        
        .custom-date-range.active,
        .custom-date-range[style*="flex"] {
            display: flex !important;
        }
        
        .date-inputs {
            display: flex;
            gap: 6px;
            align-items: center;
        }
        
        .date-inputs div {
            display: flex;
            flex-direction: column;
            gap: 3px;
        }
        
        .date-inputs label {
            font-size: 0.75rem;
            font-weight: 500;
            color: #6b7280;
        }
        
        .date-inputs input[type="date"] {
            padding: 5px 6px;
            border: 1px solid #d1d5db;
            border-radius: 4px;
            font-size: 0.7rem;
            min-width: 100px;
        }
        
        .download-list-container {
            flex: 1;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
        
        .list-header {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            margin-bottom: 10px;
            border-bottom: 1px solid #e5e7eb;
            font-size: 0.9rem;
            color: #6b7280;
            font-weight: 500;
        }
        
        .download-list {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            background: white;
        }
        
        .download-item {
            display: flex;
            padding: 15px;
            border-bottom: 1px solid #f3f4f6;
            align-items: center;
            gap: 12px;
            transition: background 0.2s ease;
        }
        
        .download-item:last-child {
            border-bottom: none;
        }
        
        .download-item:hover {
            background: #f9fafb;
        }
        
        .download-item input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        
        .item-header {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }
        
        .file-icon {
            width: 32px;
            height: 32px;
            background: #f3f4f6;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }
        
        .item-details {
            flex: 1;
        }
        
        .item-details h4 {
            margin: 0 0 6px 0;
            font-size: 0.95rem;
            color: #1f2937;
            font-weight: 600;
        }
        
        .item-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }
        
        .doc-info {
            font-size: 0.75rem;
            color: #5D0E26;
            font-weight: 600;
            background: #fef2f2;
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid #fecaca;
        }
        
        .upload-date {
            font-size: 0.75rem;
            color: #6b7280;
        }
        
        .category-badge {
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 500;
        }
        
        .category-badge.notarized-documents {
            background: #def7ec;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }
        
        .category-badge.law-office-files {
            background: #dbeafe;
            color: #1e40af;
            border: 1px solid #93c5fd;
        }
        
        .modal-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0 0 0;
            border-top: 2px solid #e5e7eb;
            margin-top: 20px;
        }
        
        .btn-select-all, .btn-clear {
            background: #6b7280;
            color: white;
            border: none;
            padding: 10px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.3s ease;
        }
        
        .btn-select-all:hover {
            background: #4b5563;
        }
        
        .btn-clear {
            background: #dc2626;
        }
        
        .btn-clear:hover {
            background: #b91c1c;
        }
        
        .btn-download {
            background: #5D0E26;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
        }
        
        .btn-download:hover:not(:disabled) {
            background: #4a0b20;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(93, 14, 38, 0.3);
        }
        
        .btn-download:disabled {
            background: #d1d5db;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .document-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(280px, 300px));
            gap: 6px;
            margin-bottom: 30px;
            align-items: stretch;
            justify-content: start;
            max-width: 100%;
            overflow-x: auto;
        }
        
        @media (max-width: 1400px) {
            .document-grid {
                grid-template-columns: repeat(4, minmax(260px, 280px));
            }
        }
        
        @media (max-width: 1200px) {
            .document-grid {
                grid-template-columns: repeat(3, minmax(300px, 1fr));
                gap: 8px;
            }
        }
        
        @media (max-width: 1000px) {
            .document-grid {
                grid-template-columns: repeat(2, minmax(45%, 1fr));
                gap: 10px;
            }
        }
        
        @media (max-width: 600px) {
            .document-grid {
                grid-template-columns: 1fr;
                gap: 12px;
            }
        }
        
        .document-card {
            background: white;
            border-radius: 16px;
            padding: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            transition: transform 0.3s, box-shadow 0.3s;
            border: 1px solid #f1f5f9;
            width: 100%;
            display: flex;
            flex-direction: column;
            height: 100%;
            position: relative;
            overflow: hidden;
        }
        
        .document-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        
        .document-card .card-header {
            display: flex;
            align-items: flex-start;
            margin-bottom: 8px;
            justify-content: space-between;
            gap: 12px;
        }
        
        .document-card .document-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .document-icon i {
            font-size: 18px;
            color: #1976d2;
        }
        
        .document-info {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        
        .document-info h3 {
            margin: 0 0 8px 0;
            font-size: 0.92rem;
            color: #111827;
            font-weight: 700;
            line-height: 1.2;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .document-meta {
            font-size: 0.78rem;
            color: #6b7280;
            line-height: 1.3;
            display: flex;
            flex-direction: column;
            gap: 4px;
            margin-top: 8px;
        }
        
        .document-meta div {
            margin-bottom: 0;
        }
        
        .document-meta strong {
            color: #374151;
            font-weight: 600;
        }
        
        .document-actions {
            display: flex;
            gap: 6px;
            margin-top: auto;
            justify-content: space-between;
            padding: 8px 0 0 0;
            border-top: 1px solid #f1f5f9;
            flex-shrink: 0;
        }
        
        .btn-action {
            padding: 10px 12px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 0.9rem;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            flex: 1;
            height: 40px;
            transition: all 0.2s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            font-weight: 600;
        }
        
        .btn-view {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            color: white;
        }
        
        .btn-edit {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
        }
        
        .btn-delete {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
        }
        
        .btn-action:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        /* Rounded corners only on first and last buttons to align with card edges */
        .btn-action:first-of-type {
            border-radius: 0 0 0 6px;
        }
        .btn-action:last-of-type {
            border-radius: 0 0 6px 0;
        }

        /* Maroon Theme for Statistics */
        .stat-number {
            color: #5D0E26 !important;
            font-weight: 700;
        }

        .stat-card {
            border-left: 4px solid #5D0E26 !important;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(93, 14, 38, 0.15);
        }
        
        .filters-section {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid #e0e0e0;
            border-left: 4px solid #5D0E26;
        }

        .filters-section h2 {
            color: #5D0E26;
            margin: 0 0 15px 0;
            font-size: 1.2rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .filters-section h2 i {
            font-size: 1rem;
        }

        .filter-group label {
            color: #5D0E26;
            font-weight: 600;
        }

        .filter-group input,
        .filter-group select {
            border: 1px solid #5D0E26 !important;
            border-radius: 6px !important;
            padding: 8px 12px !important;
            font-size: 14px !important;
            transition: all 0.3s ease !important;
        }

        .filter-group input:focus,
        .filter-group select:focus {
            border-color: #8B1538 !important;
            box-shadow: 0 0 0 2px rgba(93, 14, 38, 0.1) !important;
            outline: none !important;
        }

        .btn-primary {
            background: linear-gradient(135deg, #5D0E26, #8B1538) !important;
            border: none !important;
            color: white !important;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(93, 14, 38, 0.2);
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #4A0B1E, #6B0F2A) !important;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(93, 14, 38, 0.3);
        }
        
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .filter-group {
            display: flex;
            flex-direction: column;
        }
        
        .filter-group label {
            font-weight: 500;
            margin-bottom: 5px;
            color: #374151;
        }
        
        .filter-group input,
        .filter-group select {
            padding: 8px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 0.9rem;
        }
        
        .filter-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .btn-primary {
            background: #1976d2;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .upload-section {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .upload-section h2 {
            font-size: 1.3rem;
            margin-bottom: 15px;
            color: #1f2937;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .upload-area {
            border: 2px dashed #d1d5db;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
            transition: all 0.3s;
            background: #f9fafb;
            min-height: 100px;
        }
        
        .upload-area:hover {
            border-color: #1976d2;
            background: #f8fafc;
        }
        
        .upload-area.dragover {
            border-color: #1976d2;
            background: #eff6ff;
        }
        
        .file-preview {
            display: none;
            margin-top: 20px;
        }
        
        .preview-item {
            display: flex;
            align-items: center;
            padding: 15px;
            background: #f9fafb;
            border-radius: 8px;
            margin-bottom: 10px;
            border: 1px solid #e5e7eb;
            gap: 10px;
        }
        
        .preview-item img,
        .preview-item iframe {
            border-radius: 4px;
            border: 1px solid #d1d5db;
        }
        
        .preview-item i {
            color: #6b7280;
        }
        
        .preview-item input {
            padding: 8px 12px;
            border: 1px solid #d1d5db;
            border-radius: 4px;
            font-size: 0.9rem;
        }
        
        .preview-item button {
            background: #dc2626;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 12px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.2s;
        }
        
        .preview-item button:hover {
            background: #b91c1c;
        }
        
        /* Edit Modal Confirmation Modals - Higher z-index */
        #saveConfirmModal,
        #cancelEditConfirmModal {
            z-index: 100001 !important;
        }
        
        /* Confirmation Modal Styles - Smaller Size with !important to override conflicts */
        .modal-content.confirmation-modal {
            max-width: 350px !important;
            width: 90% !important;
            border-radius: 12px !important;
            box-shadow: 0 20px 60px rgba(93, 14, 38, 0.3) !important;
            animation: modalSlideIn 0.3s ease-out !important;
            margin: 10% auto !important;
            padding: 0 !important;
            z-index: 100001 !important;
        }

        .confirmation-modal .confirmation-content {
            text-align: center !important;
            padding: 10px 20px !important;
        }

        .confirmation-modal .confirmation-icon {
            width: 50px !important;
            height: 50px !important;
            margin: 0 auto 10px !important;
            border-radius: 50% !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            font-size: 1.3rem !important;
            color: white !important;
            background: var(--gradient-primary) !important;
            box-shadow: 0 8px 25px rgba(93, 14, 38, 0.2) !important;
        }

        .confirmation-modal .confirmation-icon.warning {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
            box-shadow: 0 8px 25px rgba(245, 158, 11, 0.3) !important;
        }

        .confirmation-modal .confirmation-icon.danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%) !important;
            box-shadow: 0 8px 25px rgba(220, 53, 69, 0.3) !important;
        }

        .confirmation-modal .confirmation-icon.success {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%) !important;
            box-shadow: 0 8px 25px rgba(40, 167, 69, 0.3) !important;
        }

        .confirmation-modal .confirmation-content h3 {
            color: #5D0E26 !important;
            font-size: 1rem !important;
            font-weight: 700 !important;
            margin: 0 0 5px 0 !important;
            line-height: 1.2 !important;
        }
        
        /* Upload Success Modal - Match admin style */
        #uploadModal .confirmation-content h3 {
            color: #5D0E26 !important;
        }
        
        #uploadErrorModal .confirmation-content h3 {
            color: #dc3545 !important;
        }

        .confirmation-modal .confirmation-content p {
            color: #666 !important;
            font-size: 0.85rem !important;
            line-height: 1.3 !important;
            margin: 0 0 10px 0 !important;
        }

        .confirmation-modal .modal-actions {
            display: flex !important;
            gap: 8px !important;
            justify-content: center !important;
            margin-top: 10px !important;
            padding: 10px 20px !important;
            border-top: 1px solid #e1e5e9 !important;
        }

        .confirmation-modal .modal-actions .btn {
            min-width: 90px !important;
            padding: 8px 16px !important;
            border-radius: 6px !important;
            font-weight: 600 !important;
            font-size: 0.8rem !important;
            cursor: pointer !important;
            transition: var(--transition) !important;
            border: none !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 4px !important;
        }

        .confirmation-modal .modal-header {
            background: linear-gradient(135deg, #5D0E26, #8B1538) !important;
            color: white !important;
            padding: 12px 20px !important;
            display: flex !important;
            justify-content: space-between !important;
            align-items: center !important;
            border-bottom: none !important;
            margin: 0 !important;
        }

        .confirmation-modal .close-modal-btn {
            color: white !important;
            font-size: 18px !important;
            font-weight: bold !important;
            cursor: pointer !important;
            transition: var(--transition) !important;
            width: 26px !important;
            height: 26px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            border-radius: 50% !important;
            background: rgba(255, 255, 255, 0.1) !important;
        }

        .confirmation-modal .close-modal-btn:hover {
            background: rgba(255, 255, 255, 0.2) !important;
            transform: scale(1.1) !important;
        }

        .confirmation-modal .modal-header h2 {
            margin: 0 !important;
            font-size: 1rem !important;
            font-weight: 600 !important;
            display: flex !important;
            align-items: center !important;
            gap: 8px !important;
            color: white !important;
        }

        .confirmation-modal .modal-header h2 i {
            color: white !important;
            font-size: 1rem !important;
        }

        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
            box-shadow: 0 4px 16px rgba(220, 53, 69, 0.3);
        }

        .btn-danger:hover {
            background: linear-gradient(135deg, #c82333 0%, #a71e2a 100%);
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(220, 53, 69, 0.4);
        }

        /* Modern Edit Modal Styles */
        .modern-edit-modal {
            max-width: 800px !important;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(93, 14, 38, 0.3);
            border: 1px solid rgba(93, 14, 38, 0.1);
            overflow: hidden;
        }
        
        /* Override dashboard.css for Edit and Download modals */
        #editModal .modal-content {
            width: 85% !important;
            max-width: 800px !important;
        }
        
        #downloadModal .modal-content {
            width: 60% !important;
            max-width: 850px !important;
        }

        .view-modal {
            max-width: 950px !important;
            width: 85% !important;
            max-height: 90vh;
            border-radius: 16px;
            box-shadow: 0 25px 50px rgba(93, 14, 38, 0.25);
            border: none;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .document-details {
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #e2e8f0;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .detail-column {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .detail-row {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
            gap: 10px;
        }

        .detail-row:last-child {
            margin-bottom: 0;
        }

        .detail-row label {
            font-weight: 600;
            color: #374151;
            min-width: 140px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .detail-row span {
            color: #6b7280;
            font-weight: 500;
        }

        .document-preview {
            flex: 1;
            min-height: 400px;
        }

        @media (max-width: 768px) {
            .document-details {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            /* Confirmation Modal Responsive Styles */
            .modal-content.confirmation-modal {
                max-width: 320px !important;
                margin: 15% auto !important;
            }
            
            .confirmation-modal .confirmation-icon {
                width: 40px !important;
                height: 40px !important;
                font-size: 1rem !important;
            }
            
            .confirmation-modal .confirmation-content h3 {
                font-size: 0.9rem !important;
            }
            
            .confirmation-modal .confirmation-content p {
                font-size: 0.8rem !important;
            }
            
            .confirmation-modal .modal-actions {
                flex-direction: column !important;
                gap: 8px !important;
            }
            
            .confirmation-modal .modal-actions .btn {
                width: 100% !important;
                justify-content: center !important;
            }
        }

        @media (max-width: 480px) {
            /* Confirmation Modal Ultra Mobile Styles */
            .modal-content.confirmation-modal {
                max-width: 300px !important;
                margin: 20% auto !important;
            }
            
            .confirmation-modal .confirmation-icon {
                width: 35px !important;
                height: 35px !important;
                font-size: 0.9rem !important;
            }
            
            .confirmation-modal .confirmation-content h3 {
                font-size: 0.85rem !important;
            }
            
            .confirmation-modal .confirmation-content p {
                font-size: 0.75rem !important;
            }
        }

        .modal-header {
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: white;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: none;
        }

        .modal-header h2 {
            margin: 0;
            font-size: 1.1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            color: white !important;
        }

        .modal-header h2 i {
            font-size: 1.1rem;
            color: white !important;
        }

        .close-modal-btn {
            background: rgba(255, 255, 255, 0.2);
            border: none;
            color: white;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 14px;
        }

        .close-modal-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: scale(1.1);
        }

        .modal-body {
            padding: 20px;
            background: white;
        }

        .modern-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .form-group label {
            font-weight: 600;
            color: #5D0E26;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .form-group label i {
            font-size: 0.8rem;
            opacity: 0.8;
        }

        .form-group input,
        .form-group select {
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s ease;
            background: #fafafa;
        }

        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #5D0E26;
            background: white;
            box-shadow: 0 0 0 3px rgba(93, 14, 38, 0.1);
        }

        .form-group input:hover,
        .form-group select:hover {
            border-color: #8B1538;
        }

        .modal-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
            margin-top: 8px;
            padding-top: 20px;
            border-top: 1px solid #f0f0f0;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 120px;
            justify-content: center;
        }

        .btn-secondary {
            background: white !important;
            color: #6c757d !important;
            border: 1px solid #e0e0e0 !important;
            padding: 9px 18px;
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-secondary:hover {
            background: #f8f9fa !important;
            color: #495057 !important;
            border-color: #d0d0d0 !important;
        }

        .btn-primary {
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: white;
            box-shadow: 0 4px 12px rgba(93, 14, 38, 0.3);
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #4A0B1E, #6B0F2A);
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(93, 14, 38, 0.4);
        }

        .btn i {
            font-size: 0.9rem;
        }

        /* Modal overlay improvements */
        .modal {
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            display: none;
            align-items: center;
            justify-content: center;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 10000;
        }
        
        .modal.show,
        .modal[style*="flex"],
        .modal[style*="block"] {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
        }
        
        /* Ensure modal content is centered */
        .modal .modal-content {
            margin: auto !important;
            position: relative !important;
        }
        
        .download-modal {
            max-width: 850px !important;
        }
        
        /* Add proper padding to modal content */
        .modal-content {
            padding: 25px !important;
            box-sizing: border-box;
        }
        
        /* Adjust header padding to compensate */
        .modal-header {
            margin: -25px -25px 20px -25px;
        }
        
        .download-list {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            padding: 10px;
        }
        
        .download-item {
            display: flex;
            align-items: center;
            padding: 10px;
            border-bottom: 1px solid #f3f4f6;
        }
        
        .download-item:last-child {
            border-bottom: none;
        }
        
        .download-item input[type="checkbox"] {
            margin-right: 10px;
        }
        
        .download-item-info {
            flex: 1;
        }
        
        .download-item-info h4 {
            margin: 0 0 5px 0;
            font-size: 0.9rem;
        }
        
        .download-item-info p {
            margin: 0;
            font-size: 0.8rem;
            color: #6b7280;
        }
        
        .alert {
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .alert-success {
            background: #d1fae5;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }
        
        .alert-error {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fca5a5;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: #1976d2;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #6b7280;
            font-size: 0.9rem;
        }
        
        /* Override dashboard.css for document upload form */
        .preview-item input[type="text"],
        .preview-item input[type="number"],
        .preview-item select {
            width: auto !important;
            padding: 8px 12px !important;
            border: 1px solid #ced4da !important;
            border-radius: 4px !important;
            height: 36px !important;
            font-size: 0.85rem !important;
            background: white !important;
            margin: 0 !important;
            box-sizing: border-box !important;
        }
        
        .preview-item input[type="text"]:focus,
        .preview-item input[type="number"]:focus,
        .preview-item select:focus {
            outline: none !important;
            border-color: #5D0E26 !important;
            box-shadow: 0 0 0 2px rgba(93, 14, 38, 0.1) !important;
        }
        
        /* Ensure proper flex behavior */
        .preview-item > div {
            width: 100% !important;
        }

        /* Pagination Styles */
        .pagination-container {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            margin-top: 1rem;
            padding: 0.75rem;
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            border: 1px solid #e9ecef;
        }
        
        .pagination-bottom {
            margin-top: 1rem;
            margin-bottom: 0.5rem;
        }
        
        .pagination-info {
            text-align: center;
            color: #5a6c7d;
            font-weight: 600;
            font-size: 0.85rem;
        }
        
        .pagination-controls {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .pagination-btn {
            background: linear-gradient(135deg, #5D0E26 0%, #8B1538 100%);
            color: white;
            border: none;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            box-shadow: 0 2px 8px rgba(93, 14, 38, 0.3);
            font-size: 0.9rem;
        }
        
        .pagination-btn:hover:not(:disabled) {
            background: linear-gradient(135deg, #8B1538 0%, #5D0E26 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(93, 14, 38, 0.4);
        }
        
        .pagination-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
            opacity: 0.6;
        }
        
        .pagination-numbers {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        
        .page-number {
            background: white;
            color: #5D0E26;
            border: 2px solid #e9ecef;
            padding: 0.5rem 0.8rem;
            border-radius: 4px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 40px;
            text-align: center;
            font-size: 0.9rem;
        }
        
        .page-number:hover {
            background: #f8f9fa;
            border-color: #5D0E26;
            transform: translateY(-1px);
        }
        
        .page-number.active {
            background: linear-gradient(135deg, #5D0E26 0%, #8B1538 100%);
            color: white;
            border-color: #5D0E26;
            box-shadow: 0 2px 8px rgba(93, 14, 38, 0.3);
        }
        
        .pagination-settings {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            padding-top: 0.5rem;
            border-top: 1px solid #e9ecef;
        }
        
        .pagination-settings label {
            color: #5a6c7d;
            font-weight: 600;
            font-size: 0.85rem;
        }
        
        .pagination-settings select {
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 4px;
            padding: 0.5rem 0.8rem;
            color: #5D0E26;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.85rem;
        }
        
        .pagination-settings select:focus {
            outline: none;
            border-color: #5D0E26;
            box-shadow: 0 0 0 3px rgba(93, 14, 38, 0.1);
        }

        /* Hamburger Menu Styles */
        .hamburger-menu {
            display: none;
            position: fixed;
            top: 5px;
            left: 5px;
            z-index: 10001;
            background: var(--gradient-primary);
            border: none;
            border-radius: 6px;
            padding: 6px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);
            transition: all 0.3s ease;
        }

        .hamburger-menu:hover {
            transform: scale(1.05);
            box-shadow: 0 6px 20px rgba(93, 14, 38, 0.4);
        }

        .hamburger-menu i {
            color: white;
            font-size: 1.5rem;
            display: block;
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

        /* Mobile Responsive Styles */
        @media (max-width: 768px) {
            /* Hamburger Menu */
            .hamburger-menu {
                display: inline-flex;
                position: relative;
                top: auto;
                left: auto;
                padding: 8px;
                border-radius: 8px;
                align-items: center;
                justify-content: center;
                margin-right: 12px;
            }

            .hamburger-menu:hover {
                transform: translateY(-1px);
            }

            .hamburger-menu i {
                font-size: 1.4rem;
            }

            /* Sidebar */
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

            .sidebar.active .sidebar-close {
                display: flex;
            }

            .sidebar-header h2,
            .sidebar-menu span {
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

            /* Main Content */
            .main-content {
                margin-left: 0 !important;
                margin-right: 0 !important;
                width: 100% !important;
                max-width: 100vw !important;
                padding: 16px !important;
                padding-top: 20px !important;
                min-height: 100vh;
                box-sizing: border-box;
            }

            /* Header compact */
            .header {
                flex-direction: row;
                align-items: center;
                justify-content: space-between;
                gap: 10px;
                padding: 8px 16px !important;
                width: 100%;
                max-width: 100%;
                box-sizing: border-box;
            }

            .header > div:first-child {
                flex: 1;
            }

            .header h1 {
                font-size: 1.3rem !important;
                margin-bottom: 2px !important;
            }

            .header .page-subtitle {
                font-size: 0.8rem !important;
            }

            .user-info {
                align-self: center;
            }

            .user-info img {
                width: 40px !important;
                height: 40px !important;
                margin-right: 10px !important;
            }

            .user-details {
                display: none !important;
            }

            .dropdown-menu {
                right: 0 !important;
                left: auto !important;
                min-width: 160px !important;
            }

            .dropdown-toggle {
                padding: 4px 8px !important;
            }

            .dropdown-toggle i {
                font-size: 0.9rem !important;
            }

            /* Stats Grid */
            .stats-grid {
                grid-template-columns: 1fr !important;
                gap: 12px;
            }

            .stat-card {
                padding: 16px;
            }

            /* Upload Section */
            .upload-section {
                padding: 16px;
                margin-bottom: 16px;
            }

            .upload-section h2 {
                font-size: 1.1rem;
            }

            .upload-area {
                padding: 16px;
                min-height: 80px;
            }

            .upload-area i {
                font-size: 1.5rem !important;
            }

            .upload-area h3 {
                font-size: 0.95rem !important;
            }

            .upload-area p {
                font-size: 0.8rem !important;
            }

            /* Filters */
            .unified-controls-section {
                margin-bottom: 16px;
            }

            .category-tabs {
                flex-direction: column;
                gap: 8px;
                padding: 16px;
            }

            .tab-btn {
                padding: 10px 16px;
                font-size: 0.85rem;
            }

            .filters-section {
                padding: 16px;
            }

            .filters-section h3 {
                font-size: 0.9rem;
            }

            .filters-grid {
                grid-template-columns: 1fr !important;
                gap: 12px;
            }

            .filter-group label {
                font-size: 0.85rem;
            }

            .filter-group input,
            .filter-group select {
                font-size: 0.85rem;
                padding: 8px;
            }

            .filter-actions {
                flex-direction: column;
                gap: 8px;
            }

            .filter-actions button,
            .filter-actions a {
                width: 100%;
                justify-content: center;
            }

            /* Document Grid */
            .document-grid {
                grid-template-columns: 1fr !important;
                gap: 8px;
            }

            .document-card {
                padding: 8px;
            }

            .document-card .card-header {
                flex-direction: row;
                align-items: center;
                margin-bottom: 6px;
                gap: 8px;
            }

            .document-icon {
                width: 32px !important;
                height: 32px !important;
            }

            .document-icon i {
                font-size: 14px !important;
            }

            .document-info h3 {
                font-size: 0.8rem;
                line-height: 1.2;
            }

            .document-meta {
                font-size: 0.7rem;
            }

            .document-meta > div {
                padding: 3px 6px !important;
                font-size: 0.65rem !important;
            }

            .document-actions {
                flex-wrap: wrap;
                gap: 3px;
                padding-top: 6px;
            }

            .btn-action {
                flex: 1 1 calc(50% - 2px);
                min-width: 0;
                padding: 6px 4px;
                font-size: 0.7rem;
                height: 32px;
                border-radius: 6px;
            }

            .btn-action i {
                font-size: 0.8rem;
            }

            /* Remove rounded corners from first/last buttons on mobile */
            .btn-action:first-of-type,
            .btn-action:last-of-type {
                border-radius: 6px !important;
            }

            /* Modals */
            .modal-content {
                width: 95% !important;
                max-width: 95% !important;
                margin: 5% auto !important;
            }

            .modern-edit-modal,
            .download-modal,
            .view-modal {
                width: 95% !important;
                max-width: 95% !important;
            }

            .modal-header h2 {
                font-size: 1rem !important;
            }

            .modal-body {
                padding: 16px !important;
            }

            .form-group label {
                font-size: 0.85rem !important;
            }

            .form-group input,
            .form-group select {
                font-size: 0.85rem !important;
                padding: 10px !important;
            }

            .modal-actions {
                flex-direction: column;
                gap: 8px;
            }

            .modal-actions .btn {
                width: 100%;
                min-width: 0;
            }

            /* Document Details in Modal */
            .document-details {
                grid-template-columns: 1fr !important;
                gap: 12px;
            }

            .detail-row {
                flex-direction: column;
                align-items: flex-start;
                gap: 4px;
            }

            .detail-row label {
                min-width: 0;
            }

            /* Download Modal */
            .date-filter-section {
                padding: 12px;
            }

            .filter-tabs {
                flex-direction: column;
                gap: 6px;
            }

            .filter-btn {
                width: 100%;
                text-align: center;
            }

            .custom-date-range {
                flex-direction: column;
                width: 100%;
                margin-left: 0;
            }

            .date-inputs {
                flex-direction: column;
                width: 100%;
            }

            .date-inputs div {
                width: 100%;
            }

            .date-inputs input {
                width: 100%;
            }

            .download-list {
                max-height: 250px;
            }

            .download-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }

            .item-header {
                flex-direction: column;
                align-items: flex-start;
                width: 100%;
            }

            .modal-footer {
                flex-direction: column;
                gap: 8px;
            }

            .modal-footer button {
                width: 100%;
            }

            /* File Preview */
            .preview-item {
                padding: 12px;
            }

            .preview-item > div {
                flex-direction: column;
            }

            .preview-item input,
            .preview-item select {
                width: 100% !important;
                font-size: 0.8rem !important;
            }

            .category-row {
                flex-direction: column !important;
                align-items: stretch !important;
            }

            .category-row select {
                width: 100% !important;
                flex: none !important;
            }

            #lawOfficeFields,
            #notarizedFields {
                width: 100%;
            }

            #notarizedFields > div {
                flex-wrap: wrap;
            }

            #notarizedFields input,
            #notarizedFields select {
                flex: 1 1 100% !important;
                min-width: 100% !important;
            }

            /* Pagination */
            .pagination-container {
                padding: 12px;
            }

            .pagination-controls {
                flex-direction: column;
                gap: 8px;
            }

            .pagination-numbers {
                flex-wrap: wrap;
                justify-content: center;
            }

            .pagination-btn {
                width: 100%;
                justify-content: center;
            }
        }

        @media (max-width: 480px) {
            /* Extra small screens */
            .hamburger-menu {
                top: 4px;
                left: 4px;
                padding: 5px;
            }

            .hamburger-menu i {
                font-size: 1rem;
            }

            .main-content {
                padding: 16px 12px 16px 12px !important;
                padding-top: 16px !important;
            }

            /* Header even more compact */
            .header {
                padding: 6px 12px !important;
            }

            .header h1 {
                font-size: 1.1rem !important;
            }

            .header .page-subtitle {
                font-size: 0.75rem !important;
            }

            .user-info img {
                width: 36px !important;
                height: 36px !important;
                margin-right: 8px !important;
            }

            .dropdown-menu {
                min-width: 140px !important;
                font-size: 0.85rem !important;
            }

            .dropdown-menu a {
                padding: 8px 12px !important;
                font-size: 0.85rem !important;
            }

            .stat-card {
                padding: 12px;
            }

            .stat-number {
                font-size: 1.5rem;
            }

            .stat-label {
                font-size: 0.8rem;
            }

            .upload-section h2 {
                font-size: 1rem;
            }

            .tab-btn {
                padding: 8px 12px;
                font-size: 0.8rem;
            }

            /* Document Cards - Even More Compact */
            .document-grid {
                gap: 6px;
            }

            .document-card {
                padding: 6px;
            }

            .document-card .card-header {
                margin-bottom: 4px;
                gap: 6px;
            }

            .document-icon {
                width: 28px !important;
                height: 28px !important;
            }

            .document-icon i {
                font-size: 12px !important;
            }

            .document-info h3 {
                font-size: 0.75rem;
            }

            .document-meta {
                font-size: 0.65rem;
            }

            .document-meta > div {
                padding: 2px 5px !important;
                font-size: 0.6rem !important;
            }

            .document-actions {
                gap: 2px;
                padding-top: 4px;
            }

            .btn-action {
                padding: 5px 3px;
                font-size: 0.65rem;
                height: 28px;
                border-radius: 5px;
            }

            .btn-action i {
                font-size: 0.75rem;
            }

            /* Rounded corners for mobile buttons */
            .btn-action:first-of-type,
            .btn-action:last-of-type {
                border-radius: 5px !important;
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

    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <button class="sidebar-close" id="sidebarCloseBtn" aria-label="Close menu">
            <i class="fas fa-times"></i>
        </button>
                <div class="sidebar-header">
            <img src="images/logo.jpg" alt="Logo">
            <h2>Opiña Law Office</h2>
        </div>
        <ul class="sidebar-menu">
            <li><a href="employee_dashboard.php"><i class="fas fa-home"></i><span>Dashboard</span></a></li>
            <li><a href="employee_documents.php" class="active"><i class="fas fa-file-alt"></i><span>Document Storage</span></a></li>
            <li><a href="employee_schedule.php"><i class="fas fa-calendar-alt"></i><span>Scheduling</span></a></li>
            <li class="has-submenu">
                <a href="#" class="submenu-toggle"><i class="fas fa-file-alt"></i><span>Document Generation</span><i class="fas fa-chevron-down submenu-arrow"></i></a>
                <ul class="submenu">
                    <li><a href="employee_document_generation.php"><i class="fas fa-file-plus"></i><span>Generate Documents</span></a></li>
                    <li><a href="employee_send_files.php"><i class="fas fa-paper-plane"></i><span>Sent Files</span></a></li>
                </ul>
            </li>
            <li><a href="employee_clients.php"><i class="fas fa-users"></i><span>Client Management</span></a></li>
            <li>
                <a href="employee_request_management.php">
                    <i class="fas fa-clipboard-check"></i><span>Request Review</span>
                    <?php if ($pending_requests_count > 0): ?>
                        <span class="notification-badge"><?= $pending_requests_count ?></span>
                    <?php endif; ?>
                </a>
            </li>
            <li><a href="employee_messages.php" class="has-badge"><i class="fas fa-envelope"></i><span>Messages</span><span class="unread-message-badge hidden" id="unreadMessageBadge">0</span></a></li>
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <?php 
        $page_title = 'Advanced Document Storage';
        $page_subtitle = 'Upload, manage, and organize documents with advanced features';
        include 'components/profile_header.php'; 
        ?>

        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number"><?= count($documents) ?></div>
                <div class="stat-label">Total Documents</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?= get_current_book_number() ?></div>
                <div class="stat-label">Current Book</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?= get_next_doc_number($conn, get_current_book_number()) - 1 ?></div>
                <div class="stat-label">Last Doc Number</div>
            </div>
        </div>

        <!-- Alerts -->
        <?php if (!empty($success)): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?= $success ?>
            </div>
        <?php endif; ?>
        
        <?php if (!empty($error)): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <?= $error ?>
            </div>
        <?php endif; ?>

        <!-- Upload Section -->
        <div class="upload-section">
            <h2><i class="fas fa-upload"></i> Upload Documents</h2>
            <form method="POST" enctype="multipart/form-data" id="uploadForm" onsubmit="return handleUploadSubmit(event)">
                <div class="upload-area" id="uploadArea">
                    <i class="fas fa-cloud-upload-alt" style="font-size: 2rem; color: #6b7280; margin-bottom: 10px;"></i>
                    <h3 style="font-size: 1.1rem; margin-bottom: 5px;">Drag & Drop Files Here</h3>
                    <p style="font-size: 0.9rem; color: #6b7280;">or click to select files (PDF, Word documents only - up to 10 documents)</p>
                    <input type="file" name="documents[]" id="fileInput" multiple accept=".pdf,.doc,.docx" style="display: none;">
                </div>
                
                <div class="file-preview" id="filePreview">
                    <h4>Document Details</h4>
                <div style="background: #fef2f2; border: 1px solid #fca5a5; border-radius: 6px; padding: 8px; margin-bottom: 15px; font-size: 0.8rem;">
                    <strong>📚 Book Number:</strong> Current month is <strong><?= date('F') ?> (<?= date('n') ?>)</strong> - You can change this if needed
                </div>
                    <div id="previewList"></div>
                </div>
                
                <div style="text-align: center;">
                    <button type="submit" class="btn-primary" id="uploadBtn" style="display: none;">
                        <i class="fas fa-upload"></i> Upload Documents
            </button>
                </div>
            </form>
        </div>

        <!-- Unified Filters & Category Section -->
        <div class="unified-controls-section">
            <!-- Category Tabs -->
            <?php
            // Count documents by category
            $lawOfficeDocs = array_filter($documents, function($doc) {
                return $doc['category'] === 'Law Office Files';
            });
            
            $notarizedDocs = array_filter($documents, function($doc) {
                return $doc['category'] === 'Notarized Documents';
            });
            ?>
            
            <div class="category-tabs">
                <button class="tab-btn active" onclick="showCategory('all')">
                    <i class="fas fa-list"></i> All Documents (<?= count($documents) ?>)
                </button>
                
                <button class="tab-btn" onclick="showCategory('notarized')">
                    <i class="fas fa-file-contract"></i> Notarized Documents (<?= count($notarizedDocs) ?>)
                </button>
                
                <button class="tab-btn" onclick="showCategory('lawoffice')">
                    <i class="fas fa-folder-open"></i> Law Office Files (<?= count($lawOfficeDocs) ?>)
                </button>
            </div>

            <!-- Filters Section -->
            <div class="filters-section">
                <h3><i class="fas fa-filter"></i> Filters & Search</h3>
                <form method="GET" id="filterForm" onsubmit="return handleFilterSubmit(event)">
                    <div class="filters-grid">
                        <div class="filter-group">
                            <label>Document Name:</label>
                            <input type="text" name="name" value="<?= htmlspecialchars($filter_name) ?>" placeholder="Search by name">
                        </div>
                        <div class="filter-group">
                            <label>Doc Number:</label>
                            <input type="number" name="doc_number" value="<?= htmlspecialchars($filter_doc_number) ?>" placeholder="Enter doc number">
                        </div>
                        <div class="filter-group">
                            <label>Book Number:</label>
                            <select name="book_number">
                                <option value="">All Books</option>
                                <?php for ($i = 1; $i <= 12; $i++): ?>
                                    <option value="<?= $i ?>" <?= $filter_book_number == $i ? 'selected' : '' ?>>
                                        Book <?= $i ?> (<?= date('F', mktime(0, 0, 0, $i, 1)) ?>)
                                    </option>
                                <?php endfor; ?>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>Series (Year):</label>
                            <select name="series">
                                <option value="">All Series</option>
                                <?php foreach ($available_series as $year): ?>
                                    <option value="<?= $year ?>" <?= $filter_series == $year ? 'selected' : '' ?>>
                                        <?= $year ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>

                    <div class="filter-actions">
                        <button type="submit" class="btn-primary">
                            <i class="fas fa-search"></i> Apply Filters
                        </button>
                        <a href="employee_documents.php" class="btn-secondary">
                            <i class="fas fa-times"></i> Clear Filters
                        </a>
                        <button type="button" class="btn-secondary" onclick="openDownloadModal()">
                            <i class="fas fa-download" style="color: #8B1538;"></i> Select Download
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Documents Grid -->
        <div class="document-grid" id="documents">
            <?php if (empty($documents)): ?>
                <div style="grid-column: 1 / -1; text-align: center; padding: 40px;">
                    <i class="fas fa-folder-open" style="font-size: 3rem; color: #d1d5db; margin-bottom: 15px;"></i>
                    <h3 style="color: #6b7280;">No documents found</h3>
                    <p style="color: #9ca3af;">Try adjusting your filters or upload some documents.</p>
                </div>
            <?php else: ?>
            <?php foreach ($documents as $doc): ?>
                    <div class="document-card" data-category="<?= htmlspecialchars($doc['category']) ?>">
                        <div class="card-header">
                            <div class="document-icon" style="margin-right: 8px !important; padding-right: 0px !important;">
                                <?php 
                                $ext = strtolower(pathinfo($doc['file_name'], PATHINFO_EXTENSION));
                                if($ext === 'pdf'): ?>
                                    <i class="fas fa-file-pdf" style="color: #d32f2f;"></i>
                        <?php elseif($ext === 'doc' || $ext === 'docx'): ?>
                                    <i class="fas fa-file-word" style="color: #1976d2;"></i>
                        <?php elseif($ext === 'xls' || $ext === 'xlsx'): ?>
                                    <i class="fas fa-file-excel" style="color: #388e3c;"></i>
                        <?php else: ?>
                            <i class="fas fa-file-alt"></i>
                        <?php endif; ?>
                    </div>
                    <div class="document-info">
                                 <h3 title="<?= htmlspecialchars($doc['document_name'] ?? $doc['file_name']) ?>"><?= htmlspecialchars(truncate_document_name($doc['document_name'] ?? $doc['file_name'])) ?></h3>
                        <div class="document-meta">
                            <?php 
                            $category_colors = [
                                'Notarized Documents' => ['bg' => '#5D0E26', 'text' => 'white'],
                                'Law Office Files' => ['bg' => '#059669', 'text' => 'white']
                            ];
                            $colors = $category_colors[$doc['category']] ?? ['bg' => '#6b7280', 'text' => 'white'];
                            ?>
                            <div style="font-size: 0.7rem; color: <?= $colors['text'] ?>; font-weight: 600; background: <?= $colors['bg'] ?>; padding: 4px 8px; border-radius: 6px; display: inline-block; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                <?= htmlspecialchars($doc['category']) ?>
                            </div>
                            <div style="font-size: 0.75rem; color: #6b7280; font-weight: 500; margin-top: 4px;">
                                <strong>Date Uploaded:</strong> <?= date('M d, Y', strtotime($doc['upload_date'])) ?>
                            </div>
                        </div>
                    </div>
                    </div>

                        <div class="document-actions">
                            <button onclick="openViewModal('<?= htmlspecialchars($doc['file_path'], ENT_QUOTES) ?>', '<?= htmlspecialchars($doc['document_name'] ?? $doc['file_name'], ENT_QUOTES) ?>', '<?= htmlspecialchars($doc['category'], ENT_QUOTES) ?>', '<?= $doc['doc_number'] ?>', '<?= $doc['book_number'] ?>', '<?= $doc['series'] ?? '' ?>', '<?= htmlspecialchars($doc['affidavit_type'] ?? '', ENT_QUOTES) ?>', '<?= htmlspecialchars($doc['uploader_name'] ?? 'Employee', ENT_QUOTES) ?>', '<?= htmlspecialchars($doc['user_type'] ?? '', ENT_QUOTES) ?>')" class="btn-action btn-view" title="View Document">
                                <i class="fas fa-eye"></i>
                            </button>
                            <a href="<?= htmlspecialchars($doc['file_path']) ?>" download="<?= htmlspecialchars($doc['document_name'] ?? $doc['file_name'], ENT_QUOTES) ?>" onclick="currentDownloadUrl = this.href; return confirmDownload('<?= htmlspecialchars($doc['document_name'] ?? $doc['file_name'], ENT_QUOTES) ?>')" class="btn-action btn-view" title="Download Document">
                                <i class="fas fa-download"></i>
                            </a>
                            <button onclick="openEditModal(<?= $doc['id'] ?>, '<?= htmlspecialchars($doc['document_name'], ENT_QUOTES) ?>', <?= $doc['doc_number'] ?>, <?= $doc['book_number'] ?>, <?= $doc['series'] ?? date('Y') ?>, '<?= htmlspecialchars($doc['affidavit_type'], ENT_QUOTES) ?>', '<?= htmlspecialchars($doc['category'], ENT_QUOTES) ?>')" class="btn-action btn-edit" title="Edit Document">
                                <i class="fas fa-edit"></i>
                            </button>
                            <a href="?delete=<?= $doc['id'] ?>" onclick="currentDeleteUrl = this.href; return confirmDelete('<?= htmlspecialchars($doc['document_name'] ?? $doc['file_name'], ENT_QUOTES) ?>')" class="btn-action btn-delete" title="Delete Document">
                                <i class="fas fa-trash"></i>
                            </a>
                </div>
        </div>
                    <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Documents Pagination -->
        <div class="pagination-container pagination-bottom" id="documentsPaginationContainer" style="display: none;">
            <div class="pagination-info">
                <span id="paginationInfo">Showing documents</span>
            </div>
            <div class="pagination-controls">
                <button class="pagination-btn" id="prevBtn" onclick="changePage(-1)">
                    <i class="fas fa-chevron-left"></i> Previous
                </button>
                <div class="pagination-numbers" id="paginationNumbers"></div>
                <button class="pagination-btn" id="nextBtn" onclick="changePage(1)">
                    Next <i class="fas fa-chevron-right"></i>
                </button>
            </div>
            <div class="pagination-settings">
                <label for="itemsPerPage">Per page:</label>
                <select id="itemsPerPage" onchange="updateItemsPerPage()">
                    <option value="10" selected>10</option>
                    <option value="20">20</option>
                    <option value="50">50</option>
                </select>
            </div>
        </div>
    </div>

    <!-- Edit Success Confirmation Modal -->
    <div id="editSuccessModal" class="modal">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-check-circle"></i> Success</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon success">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <h3>Document Updated Successfully!</h3>
                    <p id="editSuccessText">The document has been updated successfully.</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-primary" onclick="closeEditSuccessModal()">
                        <i class="fas fa-check"></i> OK
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Bulk Download Confirmation Modal -->
    <div id="bulkDownloadConfirmModal" class="modal">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-download"></i> Bulk Download Confirmation</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon">
                        <i class="fas fa-download"></i>
                    </div>
                    <h3>Do you want to download the selected documents?</h3>
                    <p id="bulkDownloadConfirmText">This will create a ZIP file containing all selected documents.</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeBulkDownloadConfirmModal()">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                    <button type="button" class="btn btn-primary" onclick="proceedBulkDownload()">
                        <i class="fas fa-download"></i> Download ZIP
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Download Confirmation Modal -->
    <div id="downloadConfirmModal" class="modal">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-download"></i> Download Confirmation</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon">
                        <i class="fas fa-download"></i>
                    </div>
                    <h3>Do you want to download this document?</h3>
                    <p id="downloadConfirmText">Are you sure you want to download this document?</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeDownloadConfirmModal()">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                    <button type="button" class="btn btn-primary" onclick="proceedDownload()">
                        <i class="fas fa-download"></i> Download
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal (First Step) -->
    <div id="deleteConfirmModal" class="modal">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-exclamation-triangle"></i> Delete Confirmation</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon warning">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <h3>Are you sure you want to delete this document?</h3>
                    <p id="deleteConfirmText">This action cannot be undone!</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeDeleteConfirmModal()">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                    <button type="button" class="btn btn-danger" onclick="proceedToSecondDeleteConfirm()">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal (Second Step) -->
    <div id="deleteFinalConfirmModal" class="modal">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-exclamation-circle"></i> Final Confirmation</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon danger">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <h3>Please confirm again to permanently delete this document.</h3>
                    <p id="deleteFinalConfirmText">This action CANNOT be undone!</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-secondary" onclick="closeDeleteFinalConfirmModal()">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                    <button type="button" class="btn btn-danger" onclick="proceedDelete()">
                        <i class="fas fa-trash"></i> Delete Permanently
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Save Changes Confirmation Modal -->
    <div id="saveConfirmModal" class="modal">
        <div class="modal-content confirmation-modal">
            <div class="confirmation-content">
                <div class="confirmation-icon warning">
                    <i class="fas fa-save"></i>
                </div>
                <h3>Save Changes?</h3>
                <p>Are you sure you want to save these changes? This will update the document information.</p>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeSaveConfirmModal()">
                    <i class="fas fa-times"></i> Cancel
                </button>
                <button class="btn btn-primary" onclick="proceedSave()">
                    <i class="fas fa-check"></i> Yes, Save Changes
                </button>
            </div>
        </div>
    </div>

    <!-- Cancel Edit Confirmation Modal -->
    <div id="cancelEditConfirmModal" class="modal">
        <div class="modal-content confirmation-modal">
            <div class="confirmation-content">
                <div class="confirmation-icon warning">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <h3>Cancel Editing?</h3>
                <p>Are you sure you want to cancel? Any unsaved changes will be lost.</p>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeCancelEditConfirmModal()">
                    <i class="fas fa-times"></i> No, Continue Editing
                </button>
                <button class="btn btn-danger" onclick="proceedCancelEdit()">
                    <i class="fas fa-check"></i> Yes, Discard Changes
                </button>
            </div>
        </div>
    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content modern-edit-modal">
            <div class="modal-header">
                <h2><i class="fas fa-edit"></i> Edit Document</h2>
            </div>
            <div class="modal-body">
                <form method="POST" class="modern-form" id="editForm" onsubmit="return confirmSaveEmployee()">
                    <input type="hidden" name="edit_id" id="edit_id">
                    
                    <!-- Error Display Area -->
                    <div id="editErrorDisplay" style="display: none; background: #fee; border: 1px solid #fb7185; border-radius: 6px; padding: 12px; margin-bottom: 20px;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <i class="fas fa-exclamation-circle" style="color: #dc2626; font-size: 16px;"></i>
                            <span id="editErrorText" style="color: #dc2626; font-weight: 500; font-size: 14px;"></span>
                        </div>
                    </div>
                    
                    <!-- Two Column Layout -->
                    <div class="document-details" style="margin-bottom: 0;">
                        <!-- Left Column -->
                        <div class="detail-column">
                    <div class="form-group">
                        <label for="edit_document_name">
                            <i class="fas fa-file-alt"></i> Document Name
                        </label>
                        <input type="text" name="edit_document_name" id="edit_document_name" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_doc_number">
                            <i class="fas fa-hashtag"></i> Doc Number
                        </label>
                        <input type="number" name="edit_doc_number" id="edit_doc_number" required onchange="clearEditError()">
                    </div>
                    <div class="form-group">
                        <label for="edit_book_number">
                            <i class="fas fa-book"></i> Book Number
                        </label>
                        <input type="number" name="edit_book_number" id="edit_book_number" required onchange="clearEditError()">
                    </div>
                        </div>
                        
                        <!-- Right Column -->
                        <div class="detail-column">
                    <div class="form-group">
                        <label for="edit_series">
                            <i class="fas fa-calendar-alt"></i> Series (Year)
                        </label>
                        <input type="number" name="edit_series" id="edit_series" min="1900" max="2100" required onchange="clearEditError()">
                    </div>
                    <div class="form-group">
                        <label for="edit_affidavit_type">
                            <i class="fas fa-file-contract"></i> Type of Affidavit
                        </label>
                        <select name="edit_affidavit_type" id="edit_affidavit_type" required onchange="clearEditError()" style="width: 100%; padding: 12px 16px; border: 2px solid #e1e5e9; border-radius: 8px; font-size: 14px; transition: all 0.3s ease; background: #fafafa;">
                            <option value="">Select Affidavit Type</option>
                            <optgroup label="1. Personal Affidavits">
                                <option value="Affidavit of Loss">Affidavit of Loss</option>
                                <option value="Affidavit of Loss Senior Citizen ID">Affidavit of Loss Senior Citizen ID</option>
                                <option value="Affidavit of Loss PWD ID">Affidavit of Loss PWD ID</option>
                                <option value="Affidavit of Loss School ID">Affidavit of Loss School ID</option>
                                <option value="Affidavit of Loss Booklet">Affidavit of Loss Booklet</option>
                                <option value="Affidavit of Loss License">Affidavit of Loss License</option>
                                <option value="Sworn Affidavit of Solo Parent">Sworn Affidavit of Solo Parent</option>
                                <option value="Sworn Affidavit of Mother">Sworn Affidavit of Mother</option>
                                <option value="Sworn Affidavit of Father">Sworn Affidavit of Father</option>
                                <option value="Sworn Affidavit of Guardian">Sworn Affidavit of Guardian</option>
                                <option value="Affidavit of Residency">Affidavit of Residency</option>
                                <option value="Affidavit of Guardianship">Affidavit of Guardianship</option>
                                <option value="Affidavit of No Income">Affidavit of No Income</option>
                                <option value="Affidavit of Low Income">Affidavit of Low Income</option>
                                <option value="Affidavit of Discrepancy">Affidavit of Discrepancy</option>
                                <option value="Affidavit of No Marriage">Affidavit of No Marriage</option>
                                <option value="Affidavit of Single Status">Affidavit of Single Status</option>
                                <option value="Affidavit of Legitimation">Affidavit of Legitimation</option>
                                <option value="Affidavit of Change of Name">Affidavit of Change of Name</option>
                                <option value="Affidavit of Support and Consent">Affidavit of Support and Consent</option>
                                <option value="Affidavit of Undertaking">Affidavit of Undertaking</option>
                                <option value="Affidavit of Desistance">Affidavit of Desistance</option>
                                <option value="Affidavit of Service">Affidavit of Service</option>
                                <option value="Affidavit of Publication">Affidavit of Publication</option>
                                <option value="Affidavit of Two Disinterested Persons">Affidavit of Two Disinterested Persons</option>
                                <option value="Affidavit of Two Disinterested Persons for Birth Verification">Affidavit of Two Disinterested Persons for Birth Verification</option>
                                <option value="Affidavit of Two Disinterested Persons for Death Verification">Affidavit of Two Disinterested Persons for Death Verification</option>
                            </optgroup>
                            <optgroup label="2. Joint Affidavits">
                                <option value="Joint Affidavit of Two Disinterested Persons">Joint Affidavit of Two Disinterested Persons</option>
                                <option value="Joint Affidavit of Two Disinterested Persons for Solo Parent">Joint Affidavit of Two Disinterested Persons for Solo Parent</option>
                                <option value="Joint Affidavit of Two Disinterested Persons for Lost ID">Joint Affidavit of Two Disinterested Persons for Lost ID</option>
                                <option value="Joint Affidavit of Cohabitation">Joint Affidavit of Cohabitation</option>
                                <option value="Joint Affidavit of Legitimation">Joint Affidavit of Legitimation</option>
                                <option value="Joint Affidavit of Support">Joint Affidavit of Support</option>
                            </optgroup>
                            <optgroup label="3. Contracts and Agreements">
                                <option value="Non Disclosure Agreement">Non Disclosure Agreement</option>
                                <option value="Memorandum of Agreement">Memorandum of Agreement</option>
                                <option value="Memorandum of Understanding">Memorandum of Understanding</option>
                                <option value="Contract of Lease">Contract of Lease</option>
                                <option value="Contract of Rent">Contract of Rent</option>
                                <option value="Contract of Employment">Contract of Employment</option>
                                <option value="Service Contract">Service Contract</option>
                                <option value="Loan Agreement">Loan Agreement</option>
                                <option value="Promissory Note">Promissory Note</option>
                                <option value="Business Partnership Agreement">Business Partnership Agreement</option>
                                <option value="Service Level Agreement">Service Level Agreement</option>
                                <option value="Consultancy Agreement">Consultancy Agreement</option>
                                <option value="Supply Agreement">Supply Agreement</option>
                                <option value="Sales Agreement">Sales Agreement</option>
                            </optgroup>
                            <optgroup label="4. Property and Financial Documents">
                                <option value="Deed of Sale Land">Deed of Sale Land</option>
                                <option value="Deed of Sale House">Deed of Sale House</option>
                                <option value="Deed of Sale Vehicle">Deed of Sale Vehicle</option>
                                <option value="Deed of Donation">Deed of Donation</option>
                                <option value="Deed of Assignment">Deed of Assignment</option>
                                <option value="Deed of Absolute Sale">Deed of Absolute Sale</option>
                                <option value="Deed of Exchange">Deed of Exchange</option>
                                <option value="Real Estate Mortgage">Real Estate Mortgage</option>
                                <option value="Chattel Mortgage">Chattel Mortgage</option>
                                <option value="Extrajudicial Settlement of Estate">Extrajudicial Settlement of Estate</option>
                                <option value="Quitclaim">Quitclaim</option>
                                <option value="Waiver of Rights">Waiver of Rights</option>
                                <option value="Authorization to Sell">Authorization to Sell</option>
                                <option value="Authorization to Transfer">Authorization to Transfer</option>
                                <option value="Special Power of Attorney">Special Power of Attorney</option>
                                <option value="General Power of Attorney">General Power of Attorney</option>
                            </optgroup>
                            <optgroup label="5. Business and Corporate Documents">
                                <option value="Articles of Incorporation">Articles of Incorporation</option>
                                <option value="Articles of Partnership">Articles of Partnership</option>
                                <option value="Board Resolution">Board Resolution</option>
                                <option value="Secretary's Certificate">Secretary's Certificate</option>
                                <option value="Business Registration Authorization">Business Registration Authorization</option>
                                <option value="Employment Certification">Employment Certification</option>
                                <option value="Bidding Documents">Bidding Documents</option>
                                <option value="Supplier Accreditation Form">Supplier Accreditation Form</option>
                                <option value="Company Undertaking">Company Undertaking</option>
                                <option value="Compliance Certificate">Compliance Certificate</option>
                            </optgroup>
                            <optgroup label="6. Legal and Government Related Documents">
                                <option value="Complaint">Complaint</option>
                                <option value="Counter Affidavit">Counter Affidavit</option>
                                <option value="Police Clearance Affidavit">Police Clearance Affidavit</option>
                                <option value="NBI Clearance Affidavit">NBI Clearance Affidavit</option>
                                <option value="Barangay Clearance Affidavit">Barangay Clearance Affidavit</option>
                                <option value="Statement of Assets and Liabilities">Statement of Assets and Liabilities</option>
                                <option value="Travel Consent for Minors">Travel Consent for Minors</option>
                                <option value="Waiver">Waiver</option>
                                <option value="Release">Release</option>
                                <option value="Undertaking">Undertaking</option>
                                <option value="Legal Authorization Letter">Legal Authorization Letter</option>
                            </optgroup>
                        </select>
                    </div>
                        </div>
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="modal-actions">
                        <button type="button" class="btn btn-secondary" onclick="closeEditModal()">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Save Changes
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- View Modal -->
    <div id="viewModal" class="modal">
        <div class="modal-content view-modal">
            <div class="modal-header">
                <h2><i class="fas fa-eye"></i> View Document</h2>
            </div>
            <div class="modal-body">
                <div class="document-details">
                    <div class="detail-column">
                        <div class="detail-row">
                            <label><i class="fas fa-file-alt"></i> Document Name:</label>
                            <span id="viewDocumentName"></span>
                        </div>
                        <div class="detail-row">
                            <label><i class="fas fa-folder"></i> Category:</label>
                            <span id="viewCategory"></span>
                        </div>
                        <div class="detail-row">
                            <label><i class="fas fa-user"></i> Uploaded by:</label>
                            <span id="viewUploader"></span>
                        </div>
                    </div>
                    <div class="detail-column">
                        <div class="detail-row" id="viewDocNumberRow" style="display: none;">
                            <label><i class="fas fa-hashtag"></i> Doc Number:</label>
                            <span id="viewDocNumber"></span>
                        </div>
                        <div class="detail-row" id="viewBookNumberRow" style="display: none;">
                            <label><i class="fas fa-book"></i> Book Number:</label>
                            <span id="viewBookNumber"></span>
                        </div>
                        <div class="detail-row" id="viewSeriesRow" style="display: none;">
                            <label><i class="fas fa-calendar-alt"></i> Series:</label>
                            <span id="viewSeries"></span>
                        </div>
                        <div class="detail-row" id="viewAffidavitTypeRow" style="display: none;">
                            <label><i class="fas fa-certificate"></i> Affidavit Type:</label>
                            <span id="viewAffidavitType"></span>
                        </div>
                    </div>
                </div>
                <div class="document-preview">
                    <iframe id="documentFrame" src="" width="100%" height="500px" style="border: 1px solid #ddd; border-radius: 8px;"></iframe>
                </div>
            </div>
            <div class="modal-actions">
                <button type="button" class="btn btn-secondary" onclick="closeViewModal()">
                    <i class="fas fa-times"></i> Close
                </button>
                <a id="downloadLink" href="" download class="btn btn-primary">
                    <i class="fas fa-download"></i> Download
                </a>
            </div>
        </div>
    </div>

    <!-- Download Modal -->
    <div id="downloadModal" class="modal">
        <div class="modal-content download-modal">
            <!-- Modal Header -->
            <div class="modal-header">
                <h2><i class="fas fa-download"></i> Download Documents</h2>
            </div>
            
            <!-- Date Filter Section -->
            <div class="date-filter-section">
                <div class="filter-tabs">
                    <button class="filter-btn active" onclick="setDateFilter('all')">All Documents</button>
                    <button class="filter-btn" onclick="setDateFilter('custom')">Custom Range</button>
                    
                    <!-- Date inputs next to Custom Range button -->
                    <div id="customDateRange" class="custom-date-range">
                        <div class="date-inputs">
                            <div>
                                <label>From:</label>
                                <input type="date" id="dateFrom" onchange="filterByCustomDate()">
                            </div>
                            <div>
                                <label>To:</label>
                                <input type="date" id="dateTo" onchange="filterByCustomDate()">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Documents List -->
            <div class="download-list-container">
                <div class="list-header">
                    <span class="doc-count">Documents: <span id="docCount">0</span></span>
                    <span class="selected-count">Selected: <span id="selectedCount">0</span></span>
                </div>
                
                <div class="download-list" id="downloadList">
                    <?php foreach ($documents as $doc): ?>
                        <?php if ($doc['category'] === 'Notarized Documents'): ?>
                        <div class="download-item" data-date="<?= date('Y-m-d', strtotime($doc['upload_date'])) ?>">
                            <input type="checkbox" value="<?= $doc['id'] ?>" onchange="updateSelectedCount()" 
                                   data-name="<?= htmlspecialchars($doc['file_name']) ?>" 
                                   data-path="<?= htmlspecialchars($doc['file_path']) ?>" 
                                   data-doc-number="<?= $doc['doc_number'] ?>" 
                                   data-book-number="<?= $doc['book_number'] ?>">
                            <div class="download-item-info">
                                <div class="item-header">
                                    <div class="file-icon">
                                        <?php 
                                        $ext = strtolower(pathinfo($doc['file_name'], PATHINFO_EXTENSION));
                                        if($ext === 'pdf'): ?>
                                            <i class="fas fa-file-pdf"></i>
                                        <?php elseif($ext === 'doc' || $ext === 'docx'): ?>
                                            <i class="fas fa-file-word"></i>
                                        <?php elseif($ext === 'xls' || $ext === 'xlsx'): ?>
                                            <i class="fas fa-file-excel"></i>
                                        <?php else: ?>
                                            <i class="fas fa-file-alt"></i>
                                        <?php endif; ?>
                                    </div>
                                    <div class="item-details">
                                        <h4 title="<?= htmlspecialchars($doc['document_name'] ?? $doc['file_name']) ?>"><?= htmlspecialchars(truncate_document_name($doc['document_name'] ?? $doc['file_name'])) ?></h4>
                                        <div class="item-meta">
                                            <span class="doc-info">Doc #<?= $doc['doc_number'] ?> | Book #<?= $doc['book_number'] ?></span>
                                            <span class="upload-date"><?= date('M d, Y', strtotime($doc['upload_date'])) ?></span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            </div>
            
            <!-- Modal Footer -->
            <div class="modal-footer">
                <button onclick="selectAllDownloads()" class="btn-select-all">
                    <i class="fas fa-check-square"></i> Select All
                </button>
                <button onclick="clearSelection()" class="btn-clear">
                    <i class="fas fa-times"></i> Clear Selection
                </button>
                <button onclick="downloadSelected()" class="btn-download" disabled id="downloadBtn">
                    <i class="fas fa-download"></i> Download ZIP
                </button>
            </div>
        </div>
    </div>

    <!-- Preview Modal -->
    <div id="previewModal" class="modal">
        <div class="modal-content" style="max-width: 90%; max-height: 90%;">
            <h2 id="previewTitle">Document Preview</h2>
            <div id="previewContent" style="text-align: center; margin-top: 20px;">
                <!-- Preview content will be inserted here -->
            </div>
        </div>
    </div>

    <!-- Upload Success Modal -->
    <div id="uploadModal" class="modal" style="display:none;">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-check-circle"></i> Success</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon success">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <h3>Document Uploaded Successfully!</h3>
                    <p id="uploadModalMessage">Document uploaded successfully.</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-primary" onclick="closeUploadModal()">
                        <i class="fas fa-check"></i> OK
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Upload Error Modal -->
    <div id="uploadErrorModal" class="modal" style="display:none;">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-exclamation-circle"></i> Upload Error</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon danger">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <h3>Upload Failed</h3>
                    <p id="uploadErrorModalMessage">Upload failed. Please try again.</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-primary" onclick="closeUploadErrorModal()">
                        <i class="fas fa-check"></i> OK
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- File Limit Modal -->
    <div id="fileLimitModal" class="modal" style="display:none;">
        <div class="modal-content confirmation-modal">
            <div class="modal-header">
                <h2><i class="fas fa-exclamation-triangle"></i> File Limit Reached</h2>
            </div>
            <div class="modal-body">
                <div class="confirmation-content">
                    <div class="confirmation-icon danger">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <h3>File Limit Exceeded</h3>
                    <p id="fileLimitModalMessage">Maximum 50 files allowed.</p>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn btn-primary" onclick="closeFileLimitModal()">
                        <i class="fas fa-check"></i> OK
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        // File upload handling
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const filePreview = document.getElementById('filePreview');
        const previewList = document.getElementById('previewList');
        const uploadBtn = document.getElementById('uploadBtn');

        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', handleDragOver);
        uploadArea.addEventListener('dragleave', handleDragLeave);
        uploadArea.addEventListener('drop', handleDrop);
        fileInput.addEventListener('change', handleFileSelect);

        function handleDragOver(e) {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        }

        function handleDragLeave(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
        }

        function handleDrop(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            handleFiles(files);
        }

        function handleFileSelect(e) {
            const files = e.target.files;
            handleFiles(files);
        }

        // Store file data for persistent preview
        let fileDataStore = new Map();
        let currentBookNumber = <?= date('n') ?>; // Current month

        async function convertWordToPDFPreview(file, fileId, previewItem) {
            try {
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch('temp_word_preview_converter.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success && result.data) {
                    // Convert base64 to blob
                    const byteCharacters = atob(result.data);
                    const byteNumbers = new Array(byteCharacters.length);
                    for (let i = 0; i < byteCharacters.length; i++) {
                        byteNumbers[i] = byteCharacters.charCodeAt(i);
                    }
                    const byteArray = new Uint8Array(byteNumbers);
                    const pdfBlob = new Blob([byteArray], { type: 'application/pdf' });
                    const pdfUrl = URL.createObjectURL(pdfBlob);
                    
                    // Update file data store with PDF blob
                    const fileData = fileDataStore.get(fileId);
                    fileData.url = pdfUrl;
                    fileData.type = 'application/pdf';
                    fileData.converted = true;
                    
                    // Update preview content
                    const previewDiv = previewItem.querySelector('div[style*="position: relative"]');
                    if (previewDiv) {
                        previewDiv.innerHTML = `
                            <iframe src="${pdfUrl}" style="width: 80px; height: 80px; border-radius: 4px; border: 1px solid #d1d5db;"></iframe>
                            <button type="button" onclick="openPreviewModal('${fileId}')" style="position: absolute; top: 2px; right: 2px; background: rgba(0,0,0,0.7); color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">👁</button>
                        `;
                    }
                }
            } catch (error) {
                console.error('Word to PDF conversion failed:', error);
                // Keep the Word icon if conversion fails
            }
        }

        function handleFiles(files) {
            if (files.length > 50) {
                showFileLimitModal('Maximum 50 files allowed.');
                return;
            }

            previewList.innerHTML = '';
            fileDataStore.clear(); // Clear previous data
            
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                const previewItem = document.createElement('div');
                previewItem.className = 'preview-item';
                previewItem.setAttribute('data-file-index', i);
                
                // Store file data for persistent preview
                const fileId = 'file_' + Date.now() + '_' + i;
                fileDataStore.set(fileId, {
                    file: file,
                    url: URL.createObjectURL(file),
                    name: file.name,
                    type: file.type,
                    converted: false
                });
                
                // Create preview based on file type
                let previewContent = '';
                if (file.type.startsWith('image/')) {
                    previewContent = `
                        <div style="position: relative; margin-right: 10px;">
                            <img src="${fileDataStore.get(fileId).url}" style="width: 80px; height: 80px; object-fit: cover; border-radius: 4px; border: 1px solid #d1d5db;">
                            <button type="button" onclick="openPreviewModal('${fileId}')" style="position: absolute; top: 2px; right: 2px; background: rgba(0,0,0,0.7); color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">👁</button>
                        </div>
                    `;
                } else if (file.type === 'application/pdf') {
                    previewContent = `
                        <div style="position: relative; margin-right: 10px;">
                            <iframe src="${fileDataStore.get(fileId).url}" style="width: 80px; height: 80px; border-radius: 4px; border: 1px solid #d1d5db;"></iframe>
                            <button type="button" onclick="openPreviewModal('${fileId}')" style="position: absolute; top: 2px; right: 2px; background: rgba(0,0,0,0.7); color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">👁</button>
                        </div>
                    `;
                } else if (file.type === 'application/msword' || file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                    previewContent = `
                        <div style="position: relative; margin-right: 10px;">
                            <i class="fas fa-file-word" style="font-size: 48px; color: #1976d2; width: 80px; height: 80px; display: flex; align-items: center; justify-content: center; border: 1px solid #d1d5db; border-radius: 4px; background: #f5f7fa;"></i>
                            <button type="button" onclick="openPreviewModal('${fileId}')" style="position: absolute; top: 2px; right: 2px; background: rgba(0,0,0,0.7); color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">👁</button>
                        </div>
                    `;
                } else {
                    previewContent = `
                        <div style="position: relative; margin-right: 10px;">
                            <i class="fas fa-file" style="font-size: 48px; color: #6b7280; width: 80px; height: 80px; display: flex; align-items: center; justify-content: center; border: 1px solid #d1d5db; border-radius: 4px;"></i>
                            <button type="button" onclick="openPreviewModal('${fileId}')" style="position: absolute; top: 2px; right: 2px; background: rgba(0,0,0,0.7); color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 10px; cursor: pointer;">👁</button>
                        </div>
                    `;
                }
                
                previewItem.innerHTML = `
                    <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
                        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 12px;">
                            ${previewContent}
                            <div style="flex: 1;">
                                <div style="font-size: 0.8rem; color: #495057; font-weight: 500; margin-bottom: 2px;">Document Name:</div>
                                <div style="font-size: 0.9rem; color: #212529; font-weight: 600;">${file.name}</div>
                            </div>
                            <button type="button" onclick="removePreviewItem(this)" data-file-id="${fileId}" style="background: #dc3545; color: white; border: none; border-radius: 6px; padding: 8px 12px; cursor: pointer; font-size: 0.8rem; font-weight: 500;">Remove</button>
                        </div>
                        <div class="category-row" style="display:flex; align-items:center; gap:8px; margin-bottom: 12px; width:100%;">
                            <select name="category[]" required onchange="toggleFieldsBasedOnCategory(this)" style="flex: 0 0 220px; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white;">
                                <option value="">Select Category *</option>
                                <option value="Notarized Documents">Notarized Documents</option>
                                <option value="Law Office Files">Law Office Files</option>
                            </select>
                            <!-- Law Office Files inline field -->
                            <div id="lawOfficeFields" style="display: none;">
                                <input type="text" name="document_names[]" placeholder="Enter document name/description" style="flex: 1; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white; min-width: 0;">
                            </div>
                        </div>
                        <!-- Notarized Documents Fields -->
                        <div id="notarizedFields" style="display: none;">
                            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: nowrap; width: 100%;">
                                <input type="text" name="surnames[]" placeholder="Surname" style="flex: 1; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white; min-width: 0;">
                                <input type="text" name="first_names[]" placeholder="First Name" style="flex: 1; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white; min-width: 0;">
                                <input type="text" name="middle_names[]" placeholder="Middle Name" style="flex: 1; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white; min-width: 0;">
                                <input type="number" name="doc_numbers[]" placeholder="Doc #" style="flex: 0 0 80px; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white;">
                                <input type="number" name="book_numbers[]" value="${currentBookNumber}" min="1" max="12" placeholder="Book" style="flex: 0 0 80px; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white;" title="Book Number (1-12, represents month)">
                                <input type="number" name="series[]" value="${new Date().getFullYear()}" min="1900" max="2100" placeholder="Series" style="flex: 0 0 90px; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white;" title="Series (Year)">
                                <select name="affidavit_types[]" style="flex: 1; padding: 8px 12px; border: 1px solid #ced4da; border-radius: 4px; height: 36px; font-size: 0.85rem; background: white; min-width: 0;">
                                    <option value="">Select Affidavit Type</option>
                                    <optgroup label="1. Personal Affidavits">
                                        <option value="Affidavit of Loss">Affidavit of Loss</option>
                                        <option value="Affidavit of Loss Senior Citizen ID">Affidavit of Loss Senior Citizen ID</option>
                                        <option value="Affidavit of Loss PWD ID">Affidavit of Loss PWD ID</option>
                                        <option value="Affidavit of Loss School ID">Affidavit of Loss School ID</option>
                                        <option value="Affidavit of Loss Booklet">Affidavit of Loss Booklet</option>
                                        <option value="Affidavit of Loss License">Affidavit of Loss License</option>
                                        <option value="Sworn Affidavit of Solo Parent">Sworn Affidavit of Solo Parent</option>
                                        <option value="Sworn Affidavit of Mother">Sworn Affidavit of Mother</option>
                                        <option value="Sworn Affidavit of Father">Sworn Affidavit of Father</option>
                                        <option value="Sworn Affidavit of Guardian">Sworn Affidavit of Guardian</option>
                                        <option value="Affidavit of Residency">Affidavit of Residency</option>
                                        <option value="Affidavit of Guardianship">Affidavit of Guardianship</option>
                                        <option value="Affidavit of No Income">Affidavit of No Income</option>
                                        <option value="Affidavit of Low Income">Affidavit of Low Income</option>
                                        <option value="Affidavit of Discrepancy">Affidavit of Discrepancy</option>
                                        <option value="Affidavit of No Marriage">Affidavit of No Marriage</option>
                                        <option value="Affidavit of Single Status">Affidavit of Single Status</option>
                                        <option value="Affidavit of Legitimation">Affidavit of Legitimation</option>
                                        <option value="Affidavit of Change of Name">Affidavit of Change of Name</option>
                                        <option value="Affidavit of Support and Consent">Affidavit of Support and Consent</option>
                                        <option value="Affidavit of Undertaking">Affidavit of Undertaking</option>
                                        <option value="Affidavit of Desistance">Affidavit of Desistance</option>
                                        <option value="Affidavit of Service">Affidavit of Service</option>
                                        <option value="Affidavit of Publication">Affidavit of Publication</option>
                                        <option value="Affidavit of Two Disinterested Persons">Affidavit of Two Disinterested Persons</option>
                                        <option value="Affidavit of Two Disinterested Persons for Birth Verification">Affidavit of Two Disinterested Persons for Birth Verification</option>
                                        <option value="Affidavit of Two Disinterested Persons for Death Verification">Affidavit of Two Disinterested Persons for Death Verification</option>
                                    </optgroup>
                                    <optgroup label="2. Joint Affidavits">
                                        <option value="Joint Affidavit of Two Disinterested Persons">Joint Affidavit of Two Disinterested Persons</option>
                                        <option value="Joint Affidavit of Two Disinterested Persons for Solo Parent">Joint Affidavit of Two Disinterested Persons for Solo Parent</option>
                                        <option value="Joint Affidavit of Two Disinterested Persons for Lost ID">Joint Affidavit of Two Disinterested Persons for Lost ID</option>
                                        <option value="Joint Affidavit of Cohabitation">Joint Affidavit of Cohabitation</option>
                                        <option value="Joint Affidavit of Legitimation">Joint Affidavit of Legitimation</option>
                                        <option value="Joint Affidavit of Support">Joint Affidavit of Support</option>
                                    </optgroup>
                                    <optgroup label="3. Contracts and Agreements">
                                        <option value="Non Disclosure Agreement">Non Disclosure Agreement</option>
                                        <option value="Memorandum of Agreement">Memorandum of Agreement</option>
                                        <option value="Memorandum of Understanding">Memorandum of Understanding</option>
                                        <option value="Contract of Lease">Contract of Lease</option>
                                        <option value="Contract of Rent">Contract of Rent</option>
                                        <option value="Contract of Employment">Contract of Employment</option>
                                        <option value="Service Contract">Service Contract</option>
                                        <option value="Loan Agreement">Loan Agreement</option>
                                        <option value="Promissory Note">Promissory Note</option>
                                        <option value="Business Partnership Agreement">Business Partnership Agreement</option>
                                        <option value="Service Level Agreement">Service Level Agreement</option>
                                        <option value="Consultancy Agreement">Consultancy Agreement</option>
                                        <option value="Supply Agreement">Supply Agreement</option>
                                        <option value="Sales Agreement">Sales Agreement</option>
                                    </optgroup>
                                    <optgroup label="4. Property and Financial Documents">
                                        <option value="Deed of Sale Land">Deed of Sale Land</option>
                                        <option value="Deed of Sale House">Deed of Sale House</option>
                                        <option value="Deed of Sale Vehicle">Deed of Sale Vehicle</option>
                                        <option value="Deed of Donation">Deed of Donation</option>
                                        <option value="Deed of Assignment">Deed of Assignment</option>
                                        <option value="Deed of Absolute Sale">Deed of Absolute Sale</option>
                                        <option value="Deed of Exchange">Deed of Exchange</option>
                                        <option value="Real Estate Mortgage">Real Estate Mortgage</option>
                                        <option value="Chattel Mortgage">Chattel Mortgage</option>
                                        <option value="Extrajudicial Settlement of Estate">Extrajudicial Settlement of Estate</option>
                                        <option value="Quitclaim">Quitclaim</option>
                                        <option value="Waiver of Rights">Waiver of Rights</option>
                                        <option value="Authorization to Sell">Authorization to Sell</option>
                                        <option value="Authorization to Transfer">Authorization to Transfer</option>
                                        <option value="Special Power of Attorney">Special Power of Attorney</option>
                                        <option value="General Power of Attorney">General Power of Attorney</option>
                                    </optgroup>
                                    <optgroup label="5. Business and Corporate Documents">
                                        <option value="Articles of Incorporation">Articles of Incorporation</option>
                                        <option value="Articles of Partnership">Articles of Partnership</option>
                                        <option value="Board Resolution">Board Resolution</option>
                                        <option value="Secretary's Certificate">Secretary's Certificate</option>
                                        <option value="Business Registration Authorization">Business Registration Authorization</option>
                                        <option value="Employment Certification">Employment Certification</option>
                                        <option value="Bidding Documents">Bidding Documents</option>
                                        <option value="Supplier Accreditation Form">Supplier Accreditation Form</option>
                                        <option value="Company Undertaking">Company Undertaking</option>
                                        <option value="Compliance Certificate">Compliance Certificate</option>
                                    </optgroup>
                                    <optgroup label="6. Legal and Government Related Documents">
                                        <option value="Complaint">Complaint</option>
                                        <option value="Counter Affidavit">Counter Affidavit</option>
                                        <option value="Police Clearance Affidavit">Police Clearance Affidavit</option>
                                        <option value="NBI Clearance Affidavit">NBI Clearance Affidavit</option>
                                        <option value="Barangay Clearance Affidavit">Barangay Clearance Affidavit</option>
                                        <option value="Statement of Assets and Liabilities">Statement of Assets and Liabilities</option>
                                        <option value="Travel Consent for Minors">Travel Consent for Minors</option>
                                        <option value="Waiver">Waiver</option>
                                        <option value="Release">Release</option>
                                        <option value="Undertaking">Undertaking</option>
                                        <option value="Legal Authorization Letter">Legal Authorization Letter</option>
                                    </optgroup>
                                </select>
                            </div>
                        </div>
                        
                    </div>
                `;
                previewList.appendChild(previewItem);
                
                // Convert Word files to PDF in background
                if (file.type === 'application/msword' || file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                    convertWordToPDFPreview(file, fileId, previewItem);
                }
            }
            
            filePreview.style.display = 'block';
            uploadBtn.style.display = 'inline-flex';
        }

        function removePreviewItem(button) {
            // Find the preview item container by going up to the element with data-file-index
            let previewItem = button.parentElement;
            while (previewItem && !previewItem.hasAttribute('data-file-index')) {
                previewItem = previewItem.parentElement;
            }
            
            if (!previewItem) {
                console.error('Could not find preview item container');
                return;
            }
            
            const fileIndex = previewItem.getAttribute('data-file-index');
            const fileId = button.getAttribute('data-file-id');
            
            // Clean up file data from store
            if (fileId && fileDataStore.has(fileId)) {
                const fileData = fileDataStore.get(fileId);
                if (fileData.url && fileData.url.startsWith('blob:')) {
                    URL.revokeObjectURL(fileData.url);
                }
                fileDataStore.delete(fileId);
            }
            
            // Remove the entire preview item (including all form fields)
            previewItem.remove();
            
            // Create a new FileList without the removed file
            const currentFiles = fileInput.files;
            const newFiles = [];
            for (let i = 0; i < currentFiles.length; i++) {
                if (i != fileIndex) {
                    newFiles.push(currentFiles[i]);
                }
            }
            
            // Create a new DataTransfer object to update the file input
            const dt = new DataTransfer();
            newFiles.forEach(file => dt.items.add(file));
            fileInput.files = dt.files;
            
            // Update preview indices for remaining items
            const remainingItems = previewList.children;
            for (let i = 0; i < remainingItems.length; i++) {
                remainingItems[i].setAttribute('data-file-index', i);
            }
            
            // If no more files, hide the entire preview section
            if (previewList.children.length === 0) {
                filePreview.style.display = 'none';
                uploadBtn.style.display = 'none';
                // Clear any remaining content
                previewList.innerHTML = '';
                // Also clear the file input
                fileInput.value = '';
            }
        }

        // Handle form submission with AJAX
        function handleUploadSubmit(event) {
            event.preventDefault();
            
            // First validate the form
            if (!validateUploadForm()) {
                return false;
            }
            
            // Show loading state
            const uploadBtn = document.getElementById('uploadBtn');
            const originalText = uploadBtn.innerHTML;
            uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';
            uploadBtn.disabled = true;
            
            // Create FormData
            const formData = new FormData(document.getElementById('uploadForm'));
            
            // Submit via AJAX
            fetch('employee_documents.php', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json();
                } else {
                    return response.text();
                }
            })
            .then(data => {
                // Reset button
                uploadBtn.innerHTML = originalText;
                uploadBtn.disabled = false;
                
                // Handle JSON response (new modal system)
                if (typeof data === 'object') {
                    if (data.success) {
                        // Success modal
                        showUploadModal('success', 'Upload Successful', data.message);
                        // Clear the form after modal closes
                        setTimeout(() => {
                            document.getElementById('filePreview').style.display = 'none';
                            document.getElementById('uploadBtn').style.display = 'none';
                            document.getElementById('fileInput').value = '';
                            fileDataStore.clear();
                            window.location.reload();
                        }, 2000);
                    } else {
                        // Error modal
                        showUploadModal('error', 'Upload Failed', data.message);
                        // Highlight doc number fields if duplicate error
                        if (data.message.includes('already exists')) {
                            highlightDocNumberFields();
                        }
                    }
                } else {
                    // Fallback for non-JSON responses (legacy)
                    if (data.includes('Upload Error:')) {
                        const errorMatch = data.match(/alert\('Upload Error:\\n\\n([^']+)'\)/);
                        if (errorMatch) {
                            const errorMessage = errorMatch[1].replace(/\\n/g, '\n');
                            showUploadModal('error', 'Upload Failed', errorMessage);
                        }
                    } else if (data.includes('Successfully uploaded')) {
                        const successMatch = data.match(/Successfully uploaded (\d+) document\(s\)!/);
                        if (successMatch) {
                            showUploadModal('success', 'Upload Successful', 'Documents uploaded successfully! Total uploaded: ' + successMatch[1] + '.');
                            setTimeout(() => {
                                document.getElementById('filePreview').style.display = 'none';
                                document.getElementById('uploadBtn').style.display = 'none';
                                document.getElementById('fileInput').value = '';
                                fileDataStore.clear();
                                window.location.reload();
                            }, 2000);
                        }
                    }
                }
            })
            .catch(error => {
                // Reset button
                uploadBtn.innerHTML = originalText;
                uploadBtn.disabled = false;
                showUploadModal('error', 'Upload Failed', 'Upload failed: ' + error.message);
            });
            
            return false;
        }

        // Modal functions
        function showUploadModal(type, title, message) {
            if (type === 'error') {
                const errorModal = document.getElementById('uploadErrorModal');
                const errorMessage = document.getElementById('uploadErrorModalMessage');
                if (errorModal && errorMessage) {
                    errorMessage.textContent = message || 'Upload failed. Please try again.';
                    errorModal.style.display = 'flex';
                }
            } else if (type === 'success') {
                const successModal = document.getElementById('uploadModal');
                const successMessage = document.getElementById('uploadModalMessage');
                if (successModal && successMessage) {
                    // Extract count from message if available
                    const countMatch = message.match(/(\d+)/);
                    if (countMatch) {
                        successMessage.textContent = `Successfully uploaded ${countMatch[1]} document(s)!`;
                    } else {
                        successMessage.textContent = message || 'Document uploaded successfully.';
                    }
                    successModal.style.display = 'flex';
                }
            }
        }
        
        function closeUploadErrorModal() {
            const modal = document.getElementById('uploadErrorModal');
            if (modal) {
                modal.style.display = 'none';
            }
        }

        function showFileLimitModal(message) {
            const modal = document.getElementById('fileLimitModal');
            const modalMessage = document.getElementById('fileLimitModalMessage');
            if (modal && modalMessage) {
                modalMessage.textContent = message || 'Maximum 50 files allowed.';
                modal.style.display = 'flex';
            }
        }

        function closeFileLimitModal() {
            const modal = document.getElementById('fileLimitModal');
            if (modal) {
                modal.style.display = 'none';
            }
        }

        function closeUploadModal() {
            const modal = document.getElementById('uploadModal');
            modal.style.display = 'none';
            
            // Remove error highlighting when modal closes
            removeErrorHighlighting();
            
            // Check if we need to reopen edit modal after showing error
            if (window.reopenEditModalAfterAlert) {
                window.reopenEditModalAfterAlert = false;
                document.getElementById('editModal').style.display = 'block';
            }
        }

        function highlightDocNumberFields() {
            // Find all doc number input fields and highlight them
            const docNumberInputs = document.querySelectorAll('input[name="doc_numbers[]"]');
            docNumberInputs.forEach(input => {
                input.classList.add('error-highlight');
            });
        }

        function removeErrorHighlighting() {
            // Remove error highlighting from all fields
            const highlightedFields = document.querySelectorAll('.error-highlight');
            highlightedFields.forEach(field => {
                field.classList.remove('error-highlight');
            });
        }

        // Close modal when clicking outside
        window.addEventListener('click', function(event) {
            const uploadModal = document.getElementById('uploadModal');
            const uploadErrorModal = document.getElementById('uploadErrorModal');
            const fileLimitModal = document.getElementById('fileLimitModal');
            if (event.target === uploadModal) {
                closeUploadModal();
            }
            if (event.target === uploadErrorModal) {
                closeUploadErrorModal();
            }
            if (event.target === fileLimitModal) {
                closeFileLimitModal();
            }
        });

        // Form validation with detailed error messages
        function validateUploadForm() {
            const categories = document.querySelectorAll('select[name="category[]"]');
            const errors = [];
            
            for (let i = 0; i < categories.length; i++) {
                const category = categories[i].value;
                const previewItem = categories[i].closest('.preview-item');
                
                if (!category) {
                    errors.push(`File ${i + 1}: Category is required`);
                    continue;
                }
                
                if (category === 'Notarized Documents') {
                    const surname = previewItem.querySelector('input[name="surnames[]"]');
                    const firstName = previewItem.querySelector('input[name="first_names[]"]');
                    const docNumber = previewItem.querySelector('input[name="doc_numbers[]"]');
                    const bookNumber = previewItem.querySelector('input[name="book_numbers[]"]');
                    const affidavitType = previewItem.querySelector('select[name="affidavit_types[]"]');
                    
                    if (!surname || !surname.value.trim()) {
                        errors.push(`File ${i + 1}: Surname is required`);
                    }
                    if (!firstName || !firstName.value.trim()) {
                        errors.push(`File ${i + 1}: First Name is required`);
                    }
                    if (!docNumber || !docNumber.value || docNumber.value <= 0) {
                        errors.push(`File ${i + 1}: Doc Number must be greater than 0`);
                    }
                    if (!bookNumber || !bookNumber.value || bookNumber.value < 1 || bookNumber.value > 12) {
                        errors.push(`File ${i + 1}: Book Number must be between 1-12`);
                    }
                    if (!affidavitType || !affidavitType.value) {
                        errors.push(`File ${i + 1}: Affidavit Type is required`);
                    }
                } else if (category === 'Law Office Files') {
                    const documentName = previewItem.querySelector('input[name="document_names[]"]');
                    
                    if (!documentName || !documentName.value.trim()) {
                        errors.push(`File ${i + 1}: Document name is required`);
                    }
                }
            }
            
            if (errors.length > 0) {
                showUploadModal('error', 'Validation Error', 'Please fix the following errors:\n\n' + errors.join('\n'));
                return false;
            }
            
            // Check for duplicate doc numbers in the current upload batch (Notarized Documents only)
            const docBookSeriesPairs = [];
            for (let i = 0; i < categories.length; i++) {
                const category = categories[i].value;
                
                if (category === 'Notarized Documents') {
                    const previewItem = categories[i].closest('.preview-item');
                    const docNumber = previewItem.querySelector('input[name="doc_numbers[]"]');
                    const bookNumber = previewItem.querySelector('input[name="book_numbers[]"]');
                    const seriesNumber = previewItem.querySelector('input[name="series[]"]');
                    
                    if (docNumber && bookNumber && seriesNumber) {
                        const docNum = docNumber.value;
                        const bookNum = bookNumber.value;
                        const seriesNum = seriesNumber.value;
                        const pair = `${docNum}-${bookNum}-${seriesNum}`;
                        
                        if (docBookSeriesPairs.includes(pair)) {
                            showUploadModal('error', 'Upload Failed', `Doc Number ${docNum} in Book ${bookNum} for Series ${seriesNum} is duplicated in this upload. Please use unique Doc Numbers within the same Book and Series for this upload.`);
                            highlightDocNumberFields();
                            return false;
                        }
                        docBookSeriesPairs.push(pair);
                    }
                }
            }
            
            return true;
        }

        // Preview functions
        function openPreviewModal(fileId) {
            const fileData = fileDataStore.get(fileId);
            if (!fileData) {
                showUploadModal('error', 'File Error', 'File data not found. Please reselect the files.');
                return;
            }
            
            document.getElementById('previewTitle').textContent = `Preview: ${fileData.name}`;
            const previewContent = document.getElementById('previewContent');
            
            if (fileData.type.startsWith('image/')) {
                previewContent.innerHTML = `
                    <div style="position: relative;">
                        <img src="${fileData.url}" style="max-width: 100%; max-height: 70vh; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
                    </div>
                `;
            } else if (fileData.type === 'application/pdf') {
                previewContent.innerHTML = `
                    <div style="position: relative;">
                        <iframe src="${fileData.url}" style="width: 100%; height: 70vh; border: none; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"></iframe>
                    </div>
                `;
            } else if (fileData.type === 'application/msword' || fileData.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                // Check if Word file was converted to PDF
                if (fileData.converted && fileData.type === 'application/pdf') {
                    previewContent.innerHTML = `
                        <div style="position: relative;">
                            <iframe src="${fileData.url}" style="width: 100%; height: 70vh; border: none; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"></iframe>
                        </div>
                    `;
                } else {
                    previewContent.innerHTML = `
                        <div style="padding: 40px; text-align: center; position: relative;">
                            <i class="fas fa-file-word" style="font-size: 5rem; color: #1976d2; margin-bottom: 20px;"></i>
                            <h3 style="margin-bottom: 15px; color: #1f2937;">${fileData.name}</h3>
                            <div style="background: #e3f2fd; border: 2px solid #1976d2; border-radius: 8px; padding: 20px; margin-top: 20px;">
                                <p style="color: #1565c0; margin-bottom: 10px; font-weight: 600;">
                                    <i class="fas fa-info-circle"></i> Word Document
                                </p>
                                <p style="color: #424242; margin: 0;">
                                    Word documents cannot be previewed in the browser. After upload, they will be automatically converted to PDF for viewing.
                                </p>
                            </div>
                        </div>
                    `;
                }
            } else {
                previewContent.innerHTML = `
                    <div style="padding: 40px; position: relative;">
                        <i class="fas fa-file" style="font-size: 4rem; color: #6b7280; margin-bottom: 20px;"></i>
                        <h3>${fileData.name}</h3>
                        <p>This file type cannot be previewed in the browser.</p>
                        <p>Please download the file to view its contents.</p>
                    </div>
                `;
            }
            
            document.getElementById('previewModal').style.display = 'flex';
        }

        function closePreviewModal() {
            document.getElementById('previewModal').style.display = 'none';
            // Don't clean up URLs here - keep them for persistent preview
        }

        // Modal functions
        function openEditModal(id, documentName, docNumber, bookNumber, series, affidavitType, category) {
            document.getElementById('edit_id').value = id;
            document.getElementById('edit_document_name').value = documentName;
            document.getElementById('edit_doc_number').value = docNumber;
            document.getElementById('edit_book_number').value = bookNumber;
            document.getElementById('edit_series').value = series || new Date().getFullYear();
            document.getElementById('edit_affidavit_type').value = affidavitType;
            
            // Show/hide fields based on category
            const docNumberGroup = document.getElementById('edit_doc_number').closest('.form-group');
            const bookNumberGroup = document.getElementById('edit_book_number').closest('.form-group');
            const seriesGroup = document.getElementById('edit_series').closest('.form-group');
            const affidavitTypeGroup = document.getElementById('edit_affidavit_type').closest('.form-group');
            
            if (category === 'Law Office Files') {
                // Hide notarized fields for Law Office Files and remove required attribute
                docNumberGroup.style.display = 'none';
                bookNumberGroup.style.display = 'none';
                affidavitTypeGroup.style.display = 'none';
                seriesGroup.style.display = 'none'; // Hide series for Law Office Files
                document.getElementById('edit_doc_number').required = false;
                document.getElementById('edit_book_number').required = false;
                document.getElementById('edit_affidavit_type').required = false;
                document.getElementById('edit_series').required = false;
            } else {
                // Show all fields for Notarized Documents and add required attribute
                docNumberGroup.style.display = 'block';
                bookNumberGroup.style.display = 'block';
                seriesGroup.style.display = 'block';
                affidavitTypeGroup.style.display = 'block';
                document.getElementById('edit_doc_number').required = true;
                document.getElementById('edit_book_number').required = true;
                document.getElementById('edit_series').required = true;
                document.getElementById('edit_affidavit_type').required = true;
            }
            
            // Clear any previous error
            document.getElementById('editErrorDisplay').style.display = 'none';
            
            document.getElementById('editModal').style.display = 'block';
        }
        
        function clearEditError() {
            document.getElementById('editErrorDisplay').style.display = 'none';
        }

        function closeEditModal() {
            // Show custom cancel confirmation modal
            document.getElementById('cancelEditConfirmModal').style.display = 'block';
        }

        function confirmSaveEmployee() {
            // Show custom save confirmation modal
            document.getElementById('saveConfirmModal').style.display = 'block';
            return false; // Prevent form submission until confirmed
        }

        function closeSaveConfirmModal() {
            document.getElementById('saveConfirmModal').style.display = 'none';
        }

        function proceedSave() {
            // Close confirmation modal
            document.getElementById('saveConfirmModal').style.display = 'none';
            
            // Get the form and submit it
            const editForm = document.getElementById('editForm');
            if (editForm) {
                // Temporarily remove onsubmit to avoid infinite loop
                editForm.onsubmit = null;
                editForm.submit();
            }
        }

        function closeCancelEditConfirmModal() {
            document.getElementById('cancelEditConfirmModal').style.display = 'none';
        }

        function proceedCancelEdit() {
            document.getElementById('cancelEditConfirmModal').style.display = 'none';
            document.getElementById('editModal').style.display = 'none';
        }

        // Close modals when clicking outside
        window.addEventListener('click', function(event) {
            const saveModal = document.getElementById('saveConfirmModal');
            const cancelModal = document.getElementById('cancelEditConfirmModal');
            
            if (event.target === saveModal) {
                closeSaveConfirmModal();
            }
            if (event.target === cancelModal) {
                closeCancelEditConfirmModal();
            }
        });

        function openViewModal(filePath, documentName, category, docNumber, bookNumber, series, affidavitType, uploader, userType) {
            // Set document details
            document.getElementById('viewDocumentName').textContent = documentName;
            document.getElementById('viewCategory').textContent = category;
            
            // Set uploader with user type
            if (uploader && userType) {
                document.getElementById('viewUploader').textContent = `${uploader} (${userType.charAt(0).toUpperCase() + userType.slice(1)})`;
            } else if (uploader) {
            document.getElementById('viewUploader').textContent = uploader;
            } else {
                document.getElementById('viewUploader').textContent = 'Unknown';
            }
            
            // Show/hide fields based on category
            const docNumberRow = document.getElementById('viewDocNumberRow');
            const bookNumberRow = document.getElementById('viewBookNumberRow');
            const seriesRow = document.getElementById('viewSeriesRow');
            const affidavitTypeRow = document.getElementById('viewAffidavitTypeRow');
            
            if (category === 'Notarized Documents') {
                document.getElementById('viewDocNumber').textContent = docNumber;
                document.getElementById('viewBookNumber').textContent = bookNumber;
                document.getElementById('viewSeries').textContent = series || 'N/A';
                document.getElementById('viewAffidavitType').textContent = affidavitType;
                docNumberRow.style.display = 'flex';
                bookNumberRow.style.display = 'flex';
                seriesRow.style.display = 'flex';
                affidavitTypeRow.style.display = 'flex';
            } else {
                // For Law Office Files, hide all notarized-specific fields including series
                seriesRow.style.display = 'none';
                docNumberRow.style.display = 'none';
                bookNumberRow.style.display = 'none';
                affidavitTypeRow.style.display = 'none';
            }
            
            // Set iframe source and download link
            // Word files are auto-converted to PDF, so just display normally
            document.getElementById('documentFrame').src = filePath;
            document.getElementById('downloadLink').href = filePath;
            
            // Show modal
            document.getElementById('viewModal').style.display = 'block';
        }

        function closeViewModal() {
            document.getElementById('viewModal').style.display = 'none';
            // Clear iframe to stop loading
            document.getElementById('documentFrame').src = '';
        }

        // Global variables for modal data
        let currentDownloadUrl = '';
        let currentDeleteUrl = '';
        let currentDocumentName = '';
        let currentBulkDownloadForm = null;

        function confirmDownload(documentName) {
            currentDocumentName = documentName;
            document.getElementById('downloadConfirmText').textContent = `Are you sure you want to download "${documentName}"?`;
            document.getElementById('downloadConfirmModal').style.display = 'block';
            return false; // Prevent default link behavior
        }

        function closeDownloadConfirmModal() {
            document.getElementById('downloadConfirmModal').style.display = 'none';
            currentDownloadUrl = '';
            currentDocumentName = '';
        }

        function proceedDownload() {
            if (currentDownloadUrl) {
                // Create a temporary link and trigger download
                const link = document.createElement('a');
                link.href = currentDownloadUrl;
                link.download = currentDocumentName || '';
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
            closeDownloadConfirmModal();
        }

        function confirmDelete(documentName) {
            currentDocumentName = documentName;
            document.getElementById('deleteConfirmText').textContent = `You are about to delete "${documentName}". This action cannot be undone!`;
            document.getElementById('deleteConfirmModal').style.display = 'block';
            return false; // Prevent default link behavior
        }

        function closeDeleteConfirmModal() {
            document.getElementById('deleteConfirmModal').style.display = 'none';
            currentDeleteUrl = '';
            currentDocumentName = '';
        }

        function proceedToSecondDeleteConfirm() {
            document.getElementById('deleteConfirmModal').style.display = 'none';
            document.getElementById('deleteFinalConfirmText').textContent = `You are about to PERMANENTLY DELETE "${currentDocumentName}". This action CANNOT be undone!`;
            document.getElementById('deleteFinalConfirmModal').style.display = 'block';
        }

        function closeDeleteFinalConfirmModal() {
            document.getElementById('deleteFinalConfirmModal').style.display = 'none';
            currentDeleteUrl = '';
            currentDocumentName = '';
        }

        function proceedDelete() {
            if (currentDeleteUrl) {
                window.location.href = currentDeleteUrl;
            }
            closeDeleteFinalConfirmModal();
        }

        function openDownloadModal() {
            document.getElementById('downloadModal').style.display = 'block';
            
            // Debug: Check how many download items exist
            const allItems = document.querySelectorAll('.download-item');
            console.log('Total download items found:', allItems.length);
            
            updateDocumentCount();
            updateSelectedCount();
        }

        function closeDownloadModal() {
            document.getElementById('downloadModal').style.display = 'none';
            // Reset filters
            setDateFilter('all');
        }
        
        function setDateFilter(type) {
            // Update active filter button
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            const today = new Date();
            const yesterday = new Date(today);
            yesterday.setDate(yesterday.getDate() - 1);
            
            const downloadItems = document.querySelectorAll('.download-item');
            let selectedCount = 0;
            
            downloadItems.forEach(item => {
                const uploadDate = new Date(item.getAttribute('data-date'));
                let show = false;
                
                switch(type) {
                    case 'all':
                        show = true;
                        document.getElementById('customDateRange').style.display = 'none';
                        document.getElementById('customDateRange').classList.remove('active');
                        break;
                    case 'today':
                        show = uploadDate.toDateString() === today.toDateString();
                        document.getElementById('customDateRange').style.display = 'none';
                        document.getElementById('customDateRange').classList.remove('active');
                        break;
                    case 'yesterday':
                        show = uploadDate.toDateString() === yesterday.toDateString();
                        document.getElementById('customDateRange').style.display = 'none';
                        document.getElementById('customDateRange').classList.remove('active');
                        break;
                    case 'custom':
                        const customRange = document.getElementById('customDateRange');
                        if (customRange) {
                            customRange.style.display = 'flex';
                            customRange.classList.add('active');
                            console.log('Custom range shown');
                        } else {
                            console.log('Custom range element not found');
                        }
                        // Don't filter yet, wait for user to select dates
                        show = true;
                        break;
                }
                
                item.style.display = show ? 'flex' : 'none';
                if (show) {
                    const checkbox = item.querySelector('input[type="checkbox"]');
                    if (checkbox && checkbox.checked) {
                        selectedCount++;
                    }
                }
            });
            
            updateDocumentCount();
            updateDownloadButton();
            document.getElementById('customDateRange').style.display = 'none';
        }
        
        function filterByCustomDate() {
            const fromDate = document.getElementById('dateFrom').value;
            const toDate = document.getElementById('dateTo').value;
            
            console.log('Filtering by custom date:', fromDate, 'to', toDate);
            
            if (!fromDate || !toDate) {
                console.log('Dates incomplete, showing all documents');
                // If dates not complete, show all documents
                document.querySelectorAll('.download-item').forEach(item => {
                    item.style.display = 'flex';
                });
                updateDocumentCount();
                updateSelectedCount();
                updateDownloadButton();
                return;
            }
            
            const downloadItems = document.querySelectorAll('.download-item');
            console.log('Found', downloadItems.length, 'download items');
            
            let visibleCount = 0;
            
            downloadItems.forEach(item => {
                const uploadDate = new Date(item.getAttribute('data-date'));
                const filterFrom = new Date(fromDate);
                const filterTo = new Date(toDate);
                
                console.log('Checking item:', item.querySelector('.item-details h4').textContent, 'uploaded on:', uploadDate);
                
                // Add one day to 'to' date to include the entire day
                filterTo.setDate(filterTo.getDate() + 1);
                
                const show = uploadDate >= filterFrom && uploadDate < filterTo;
                item.style.display = show ? 'flex' : 'none';
                
                if (show) {
                    visibleCount++;
                }
            });
            
            console.log('Visible documents after filtering:', visibleCount);
            
            updateDocumentCount();
            updateSelectedCount();
            updateDownloadButton();
        }
        
        function updateDocumentCount() {
            const visibleItems = document.querySelectorAll('.download-item[style*="flex"], .download-item:not([style*="none"])');
            document.getElementById('docCount').textContent = visibleItems.length;
            console.log('Updated document count:', visibleItems.length);
        }
        
        function updateSelectedCount() {
            const visibleItems = document.querySelectorAll('.download-item[style*="flex"], .download-item:not([style*="none"])');
            let selectedCount = 0;
            
            visibleItems.forEach(item => {
                const checkbox = item.querySelector('input[type="checkbox"]');
                if (checkbox && checkbox.checked) {
                    selectedCount++;
                }
            });
            
            document.getElementById('selectedCount').textContent = selectedCount;
            updateDownloadButton();
        }
        
        function updateDownloadButton() {
            const selectedCount = parseInt(document.getElementById('selectedCount').textContent);
            const downloadBtn = document.getElementById('downloadBtn');
            
            downloadBtn.disabled = selectedCount === 0;
        }
        
        function selectAllDownloads() {
            const visibleItems = document.querySelectorAll('.download-item[style*="flex"], .download-item:not([style])');
            visibleItems.forEach(item => {
                const checkbox = item.querySelector('input[type="checkbox"]');
                if (checkbox) {
                    checkbox.checked = true;
                }
            });
            updateSelectedCount();
        }
        
        function clearSelection() {
            const checkboxes = document.querySelectorAll('.download-item input[type="checkbox"]');
            checkboxes.forEach(checkbox => {
                checkbox.checked = false;
            });
            updateSelectedCount();
        }

        function selectAll() {
            const checkboxes = document.querySelectorAll('#downloadList input[type="checkbox"]');
            checkboxes.forEach(cb => cb.checked = true);
        }

        function downloadSelected() {
            const selected = document.querySelectorAll('#downloadList input[type="checkbox"]:checked');
            if (selected.length === 0) {
                // Show error in modal instead of alert
                document.getElementById('bulkDownloadConfirmText').textContent = 'Please select at least one document to download.';
                document.getElementById('bulkDownloadConfirmModal').style.display = 'block';
                return;
            }

            // Create form for bulk download
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'download_selected_documents.php';
            form.id = 'bulkDownloadForm';
            
            selected.forEach(cb => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'selected_docs[]';
                input.value = cb.value;
                form.appendChild(input);
            });
            
            document.body.appendChild(form);
            currentBulkDownloadForm = form;

            // Show confirmation modal
            document.getElementById('bulkDownloadConfirmText').textContent = `Are you sure you want to download ${selected.length} selected document(s)?\n\nThis will create a ZIP file containing all selected documents.`;
            document.getElementById('bulkDownloadConfirmModal').style.display = 'block';
        }

        function closeBulkDownloadConfirmModal() {
            document.getElementById('bulkDownloadConfirmModal').style.display = 'none';
            if (currentBulkDownloadForm) {
                document.body.removeChild(currentBulkDownloadForm);
                currentBulkDownloadForm = null;
            }
        }

        // Edit form submission is handled by confirmSaveEmployee() and proceedSave()

        function closeEditSuccessModal() {
            document.getElementById('editSuccessModal').style.display = 'none';
        }

        function showEditSuccessModal(message = 'The document has been updated successfully.') {
            document.getElementById('editSuccessText').textContent = message;
            document.getElementById('editSuccessModal').style.display = 'block';
        }

        function proceedBulkDownload() {
            if (currentBulkDownloadForm) {
                currentBulkDownloadForm.submit();
                document.body.removeChild(currentBulkDownloadForm);
                currentBulkDownloadForm = null;
            }
            closeBulkDownloadConfirmModal();
        }

        // Close modals when clicking outside
        window.onclick = function(event) {
            const editModal = document.getElementById('editModal');
            const viewModal = document.getElementById('viewModal');
            const downloadModal = document.getElementById('downloadModal');
            const previewModal = document.getElementById('previewModal');
            const downloadConfirmModal = document.getElementById('downloadConfirmModal');
            const deleteConfirmModal = document.getElementById('deleteConfirmModal');
            const deleteFinalConfirmModal = document.getElementById('deleteFinalConfirmModal');
            const bulkDownloadConfirmModal = document.getElementById('bulkDownloadConfirmModal');
            const editSuccessModal = document.getElementById('editSuccessModal');
            
            if (event.target === editModal) {
                closeEditModal();
            }
            if (event.target === viewModal) {
                closeViewModal();
            }
            if (event.target === downloadModal) {
                closeDownloadModal();
            }
            if (event.target === previewModal) {
                closePreviewModal();
            }
            if (event.target === downloadConfirmModal) {
                closeDownloadConfirmModal();
            }
            if (event.target === deleteConfirmModal) {
                closeDeleteConfirmModal();
            }
            if (event.target === deleteFinalConfirmModal) {
                closeDeleteFinalConfirmModal();
            }
            if (event.target === bulkDownloadConfirmModal) {
                closeBulkDownloadConfirmModal();
            }
            if (event.target === editSuccessModal) {
                closeEditSuccessModal();
            }
        }

        // Handle filter form submission without page reload
        function handleFilterSubmit(event) {
            event.preventDefault();
            
            // Save current scroll position
            sessionStorage.setItem('scrollPosition', window.scrollY);
            
            // Submit the form normally (this will reload the page)
            document.getElementById('filterForm').submit();
            
            return false;
        }

        // Restore scroll position after page load and handle edit modal error
        window.addEventListener('load', function() {
            const savedScrollPosition = sessionStorage.getItem('scrollPosition');
            if (savedScrollPosition) {
                window.scrollTo(0, parseInt(savedScrollPosition));
                sessionStorage.removeItem('scrollPosition');
            }
            
            // Check for edit modal error from PHP session
            <?php if ($modal_error && $edit_form_data): ?>
                // Re-populate edit form with previous data for user to retry
                document.getElementById('edit_id').value = '<?= $edit_form_data['id'] ?>';
                document.getElementById('edit_document_name').value = '<?= htmlspecialchars($edit_form_data['name']) ?>';
                document.getElementById('edit_doc_number').value = '<?= $edit_form_data['doc_number'] ?>';
                document.getElementById('edit_book_number').value = '<?= $edit_form_data['book_number'] ?>';
                document.getElementById('edit_series').value = '<?= $edit_form_data['series'] ?? date('Y') ?>';
                document.getElementById('edit_affidavit_type').value = '<?= htmlspecialchars($edit_form_data['affidavit_type']) ?>';
                
                // Display error in alert modal (not inline)
                showUploadModal('error', 'Duplicate Document', '<?= htmlspecialchars($modal_error, ENT_QUOTES) ?>');
                
                // Set flag to reopen edit modal after alert closes
                window.reopenEditModalAfterAlert = true;
            <?php endif; ?>
            
            // Check for successful edit
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('edit_success') === '1') {
                showEditSuccessModal('Changes saved successfully.');
                // Clean up URL by removing the parameter
                window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
            }
        });

        // Cleanup function for page unload
        window.addEventListener('beforeunload', function() {
            // Clean up all stored URLs to free memory
            fileDataStore.forEach((fileData, fileId) => {
                if (fileData.url && fileData.url.startsWith('blob:')) {
                    URL.revokeObjectURL(fileData.url);
                }
            });
            fileDataStore.clear();
        });
    </script>
    
    <script>
        function showCategory(category) {
            // Update active tab
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Filter documents
            const cards = document.querySelectorAll('.document-card');
            
            cards.forEach(card => {
                const cardCategory = card.getAttribute('data-category');
                
                switch(category) {
                    case 'all':
                        card.style.display = 'flex';
                        break;
                    case 'notarized':
                        card.style.display = cardCategory === 'Notarized Documents' ? 'flex' : 'none';
                        break;
                    case 'lawoffice':
                        card.style.display = cardCategory === 'Law Office Files' ? 'flex' : 'none';
                        break;
                }
            });
            
            // Show message if no documents in category
            const visibleCards = Array.from(cards).filter(card => card.style.display !== 'none');
            let noDocsMessage = document.getElementById('no-docs-message');
            
            if (visibleCards.length === 0) {
                if (!noDocsMessage) {
                    noDocsMessage = document.createElement('div');
                    noDocsMessage.id = 'no-docs-message';
                    noDocsMessage.style.cssText = 'grid-column: 1 / -1; text-align: center; padding: 40px;';
                    noDocsMessage.innerHTML = '<i class="fas fa-folder-open" style="font-size: 3rem; color: #d1d5db; margin-bottom: 15px;"></i><h3 style="color: #6b7280;">No documents in this category</h3><p style="color: #9ca3af;">Upload some documents to see them here.</p>';
                    document.getElementById('document-container').appendChild(noDocsMessage);
                }
                noDocsMessage.style.display = 'block';
            } else {
                if (noDocsMessage) {
                    noDocsMessage.style.display = 'none';
                }
            }
        }
        
        function toggleFieldsBasedOnCategory(selectElement) {
            const category = selectElement.value;
            const previewItem = selectElement.closest('.preview-item');
            
            if (!previewItem) return;
            
            const notarizedFields = previewItem.querySelector('#notarizedFields');
            const lawOfficeFields = previewItem.querySelector('#lawOfficeFields');
            const originalCategorySelect = previewItem.querySelector('select[name="category[]"]');
            
            // Sync the original category dropdown with the embedded one
            if (originalCategorySelect && originalCategorySelect !== selectElement) {
                originalCategorySelect.value = category;
            }
            
            if (category === 'Notarized Documents') {
                if (notarizedFields) notarizedFields.style.display = 'block';
                if (lawOfficeFields) lawOfficeFields.style.display = 'none';
                // keep category visible
                // Make Notarized fields required
                if (notarizedFields) {
                    notarizedFields.querySelectorAll('input, select').forEach(field => {
                        field.required = true;
                    });
                }
                // Remove required from Law Office fields
                if (lawOfficeFields) {
                    lawOfficeFields.querySelectorAll('input').forEach(field => {
                        field.required = false;
                    });
                }
            } else if (category === 'Law Office Files') {
                if (notarizedFields) notarizedFields.style.display = 'none';
                if (lawOfficeFields) {
                    lawOfficeFields.style.display = 'flex';
                    lawOfficeFields.style.flex = '1';
                    lawOfficeFields.style.gap = '8px';
                }
                // keep category visible next to the input
                if (originalCategorySelect) {
                    originalCategorySelect.style.display = 'block';
                    originalCategorySelect.style.flex = '0 0 220px';
                }
                // Remove required from Notarized fields
                if (notarizedFields) {
                    notarizedFields.querySelectorAll('input, select').forEach(field => {
                        field.required = false;
                    });
                }
                // Make Law Office fields required
                if (lawOfficeFields) {
                    lawOfficeFields.querySelectorAll('input').forEach(field => {
                        field.required = true;
                    });
                }
            } else {
                // Hide both if no category selected
                if (notarizedFields) notarizedFields.style.display = 'none';
                if (lawOfficeFields) lawOfficeFields.style.display = 'none';
                if (originalCategorySelect) originalCategorySelect.style.display = 'block';
                // Remove required from both
                if (notarizedFields) {
                    notarizedFields.querySelectorAll('input, select').forEach(field => {
                        field.required = false;
                    });
                }
                if (lawOfficeFields) {
                    lawOfficeFields.querySelectorAll('input').forEach(field => {
                        field.required = false;
                    });
                }
            }
        }
    </script>
    
    <!-- Sidebar Dropdown Script -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const submenuToggles = document.querySelectorAll('.submenu-toggle');
            
            submenuToggles.forEach(toggle => {
                toggle.addEventListener('click', function(e) {
                    e.preventDefault();
                    const submenu = this.parentElement;
                    submenu.classList.toggle('open');
                });
            });
        });

        // ========================================
        // PAGINATION LOGIC
        // ========================================
        
        let currentPage = 1;
        let itemsPerPage = 10;

        function initializePagination() {
            const cards = document.querySelectorAll('.document-card');
            if (cards.length === 0) return;
            
            document.getElementById('documentsPaginationContainer').style.display = 'flex';
            updatePagination(cards);
        }

        function updatePagination(cards = null) {
            if (!cards) cards = document.querySelectorAll('.document-card');
            const totalCards = cards.length;
            const totalPages = Math.ceil(totalCards / itemsPerPage);
            const startItem = (currentPage - 1) * itemsPerPage + 1;
            const endItem = Math.min(currentPage * itemsPerPage, totalCards);

            // Update info
            document.getElementById('paginationInfo').textContent = 
                `Showing ${startItem}-${endItem} of ${totalCards} documents`;

            // Generate page numbers
            const numbersDiv = document.getElementById('paginationNumbers');
            numbersDiv.innerHTML = '';
            for (let i = 1; i <= totalPages; i++) {
                const pageBtn = document.createElement('div');
                pageBtn.className = 'page-number' + (i === currentPage ? ' active' : '');
                pageBtn.textContent = i;
                pageBtn.onclick = () => goToPage(i);
                numbersDiv.appendChild(pageBtn);
            }

            // Update buttons
            document.getElementById('prevBtn').disabled = currentPage === 1;
            document.getElementById('nextBtn').disabled = currentPage === totalPages;

            // Show/hide cards
            cards.forEach((card, index) => {
                const cardPage = Math.floor(index / itemsPerPage) + 1;
                card.style.display = (cardPage === currentPage) ? '' : 'none';
            });
        }

        function changePage(direction) {
            const cards = document.querySelectorAll('.document-card');
            const totalPages = Math.ceil(cards.length / itemsPerPage);
            currentPage += direction;
            currentPage = Math.max(1, Math.min(currentPage, totalPages));
            updatePagination(cards);
        }

        function goToPage(page) {
            currentPage = page;
            updatePagination();
        }

        function updateItemsPerPage() {
            itemsPerPage = parseInt(document.getElementById('itemsPerPage').value);
            currentPage = 1;
            updatePagination();
        }

        // Initialize pagination on page load
        setTimeout(() => {
            initializePagination();
        }, 500);

    </script>

    <script>
        // Hamburger Menu Functions
        const sidebar = document.getElementById('sidebar');
        const sidebarOverlay = document.getElementById('sidebarOverlay');
        const hamburgerMenu = document.getElementById('hamburgerMenu');
        const headerContainer = document.querySelector('.main-content .header');
        const sidebarCloseBtn = document.getElementById('sidebarCloseBtn');
        const hamburgerIcon = hamburgerMenu ? hamburgerMenu.querySelector('i') : null;
        const hamburgerPlaceholder = document.createElement('span');

        if (hamburgerMenu && hamburgerMenu.parentNode) {
            hamburgerPlaceholder.id = 'hamburgerPlaceholder';
            hamburgerPlaceholder.style.display = 'none';
            hamburgerMenu.parentNode.insertBefore(hamburgerPlaceholder, hamburgerMenu.nextSibling);
        }

        function placeHamburger() {
            if (!hamburgerMenu) return;

            if (window.innerWidth <= 768) {
                hamburgerMenu.style.position = '';
                hamburgerMenu.style.top = '';
                hamburgerMenu.style.left = '';
                if (headerContainer && !headerContainer.contains(hamburgerMenu)) {
                    headerContainer.insertBefore(hamburgerMenu, headerContainer.firstElementChild);
                }
                hamburgerMenu.classList.add('in-header');
            } else {
                if (hamburgerMenu.classList.contains('in-header') && hamburgerPlaceholder.parentNode) {
                    hamburgerPlaceholder.parentNode.insertBefore(hamburgerMenu, hamburgerPlaceholder);
                }
                hamburgerMenu.classList.remove('in-header');
                hamburgerMenu.style.position = 'fixed';
                hamburgerMenu.style.top = '5px';
                hamburgerMenu.style.left = '5px';
                if (hamburgerIcon) {
                    hamburgerIcon.classList.remove('fa-times');
                    hamburgerIcon.classList.add('fa-bars');
                }
            }
        }

        placeHamburger();

        // Toggle sidebar
        function toggleSidebar() {
            if (!sidebar || !sidebarOverlay) return;

            sidebar.classList.toggle('active');
            sidebarOverlay.classList.toggle('active');

            const isActive = sidebar.classList.contains('active');

            if (isActive) {
                document.body.style.overflow = 'hidden';
                if (hamburgerIcon) {
                    hamburgerIcon.classList.remove('fa-bars');
                    hamburgerIcon.classList.add('fa-times');
                }
            } else {
                document.body.style.overflow = '';
                if (hamburgerIcon) {
                    hamburgerIcon.classList.remove('fa-times');
                    hamburgerIcon.classList.add('fa-bars');
                }
            }
        }

        // Close sidebar
        function closeSidebar() {
            if (!sidebar || !sidebarOverlay) return;

            sidebar.classList.remove('active');
            sidebarOverlay.classList.remove('active');
            document.body.style.overflow = '';

            if (hamburgerIcon) {
                hamburgerIcon.classList.remove('fa-times');
                hamburgerIcon.classList.add('fa-bars');
            }
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
        const sidebarLinks = document.querySelectorAll('.sidebar-menu a');
        sidebarLinks.forEach(link => {
            link.addEventListener('click', function(event) {
                if (window.innerWidth <= 768) {
                    if (link.classList.contains('submenu-toggle')) {
                        event.preventDefault();
                        return;
                    }
                    closeSidebar();
                }
            });
        });

        // Auto-close sidebar on desktop resize
        window.addEventListener('resize', function() {
            placeHamburger();
            if (window.innerWidth > 768) {
                closeSidebar();
            }
        });

        // Close sidebar on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && sidebar && sidebar.classList.contains('active')) {
                closeSidebar();
            }
        });
</script>
    <script src="assets/js/unread-messages.js?v=<?= time() ?>"></script>
</body>
</html> 
