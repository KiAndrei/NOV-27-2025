<?php
/**
 * Temporary Word to PDF Preview Converter
 * Converts Word documents to PDF for preview purposes during upload
 * Generated PDFs are temporary and will be cleaned up automatically
 */

// Start output buffering
ob_start();

// Set JSON header
header('Content-Type: application/json');

// Check request method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Check if file was uploaded
if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'No file uploaded or upload error']);
    exit;
}

// Validate file type
$file = $_FILES['file'];
$fileInfo = pathinfo($file['name']);
$extension = strtolower($fileInfo['extension'] ?? '');

if (!in_array($extension, ['doc', 'docx'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid file type. Only Word documents are supported.']);
    exit;
}

try {
    // Load PhpWord
    require_once __DIR__ . '/vendor/autoload.php';
    
    // Move uploaded file to temporary location
    $tempDir = sys_get_temp_dir();
    $tempFileName = uniqid('word_preview_', true) . '.' . $extension;
    $tempFilePath = $tempDir . '/' . $tempFileName;
    
    if (!move_uploaded_file($file['tmp_name'], $tempFilePath)) {
        throw new Exception('Failed to move uploaded file to temporary location');
    }
    
    // For .doc files, return error (PhpWord has limited support)
    if ($extension === 'doc') {
        unlink($tempFilePath);
        http_response_code(422);
        echo json_encode([
            'success' => false, 
            'error' => 'Old .doc format is not supported for preview. Please use .docx format.',
            'supported' => false
        ]);
        exit;
    }
    
    // Convert Word to PDF
    $pdfFileName = uniqid('pdf_preview_', true) . '.pdf';
    $pdfFilePath = $tempDir . '/' . $pdfFileName;
    
    // Load the Word document
    $phpWord = \PhpOffice\PhpWord\IOFactory::load($tempFilePath);
    
    // Create PDF writer using DomPDF
    \PhpOffice\PhpWord\Settings::setPdfRendererName('DomPDF');
    \PhpOffice\PhpWord\Settings::setPdfRendererPath(__DIR__ . '/vendor/dompdf/dompdf');
    
    // Save as PDF
    $pdfWriter = \PhpOffice\PhpWord\IOFactory::createWriter($phpWord, 'PDF');
    $pdfWriter->save($pdfFilePath);
    
    // Check if PDF was created successfully
    if (!file_exists($pdfFilePath) || filesize($pdfFilePath) === 0) {
        unlink($tempFilePath);
        throw new Exception('PDF conversion failed or produced empty file');
    }
    
    // Read PDF content
    $pdfContent = file_get_contents($pdfFilePath);
    
    // Clean up temporary files
    unlink($tempFilePath);
    unlink($pdfFilePath);
    
    // Return PDF as base64-encoded data
    ob_clean();
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'data' => base64_encode($pdfContent),
        'mime_type' => 'application/pdf',
        'filename' => pathinfo($file['name'], PATHINFO_FILENAME) . '.pdf'
    ]);
    
} catch (Exception $e) {
    // Clean up any remaining temp files
    if (isset($tempFilePath) && file_exists($tempFilePath)) {
        @unlink($tempFilePath);
    }
    if (isset($pdfFilePath) && file_exists($pdfFilePath)) {
        @unlink($pdfFilePath);
    }
    
    ob_clean();
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Conversion failed: ' . $e->getMessage()
    ]);
}

