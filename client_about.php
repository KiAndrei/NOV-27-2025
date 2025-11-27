<?php
require_once 'session_manager.php';
validateUserAccess('client');
require_once 'config.php';
require_once 'audit_logger.php';
require_once 'action_logger_helper.php';

$client_id = $_SESSION['user_id'];

$stmt = $conn->prepare("SELECT profile_image FROM user_form WHERE id=?");
$stmt->bind_param("i", $client_id);
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
    <title>About Us - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?= time() ?>">
    <style>
        /* About Us Page Styles */
        .about-container {
            padding: 0;
            margin: 0;
            background: #ffffff;
            color: #333;
        }
        
        .about-hero {
            background: linear-gradient(135deg, #8B1538 0%, #5D0E26 50%, rgba(139, 21, 56, 0.3) 100%);
            color: white;
            padding: 60px 40px;
            text-align: center;
            margin-bottom: 0;
            min-height: 300px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }
        
        .about-hero h1 {
            color: white;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 15px;
            font-family: "Poppins", sans-serif;
            letter-spacing: 1px;
        }
        
        .about-hero p {
            color: rgba(255, 255, 255, 0.8);
            font-size: 1.1rem;
            line-height: 1.6;
            max-width: 600px;
            margin: 0 auto;
            font-weight: 300;
        }
        
        .about-content {
            padding: 40px 40px;
            max-width: 1400px;
            margin: 0 auto;
            background: #ffffff;
        }
        
        .about-section {
            margin-bottom: 50px;
            position: relative;
        }
        
        .story-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            align-items: center;
            margin-bottom: 50px;
            padding: 30px 0;
        }
        
        .story-image {
            position: relative;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            height: 500px;
        }
        
        .story-image img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.4s ease;
        }
        
        .story-image:hover img {
            transform: scale(1.05);
        }
        
        .story-content {
            padding: 40px 0;
        }
        
        .story-content h2 {
            color: #8B1538;
            font-size: 1.2rem;
            font-weight: 500;
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .story-content h3 {
            color: #333;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 30px;
            font-family: "Poppins", sans-serif;
            line-height: 1.2;
        }
        
        .story-content p {
            color: #666;
            font-size: 1.1rem;
            line-height: 1.8;
            margin-bottom: 25px;
        }
        
        .story-content .cta-button {
            background: #8B1538;
            color: white;
            padding: 15px 30px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            display: inline-block;
            margin-top: 20px;
            transition: all 0.3s ease;
        }
        
        .story-content .cta-button:hover {
            background: #5D0E26;
            color: white;
            transform: translateY(-2px);
        }
        
        .about-section h2 {
            color: #333;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 25px;
            font-family: "Poppins", sans-serif;
            text-align: center;
        }
        
        .about-section p {
            color: #666;
            font-size: 1.1rem;
            line-height: 1.8;
            margin-bottom: 25px;
            text-align: center;
            max-width: 800px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .mission-content {
            margin-top: 40px;
            position: relative;
        }
        
        .mission-intro {
            color: #333;
            font-size: 1.3rem;
            line-height: 1.8;
            margin-bottom: 50px;
            text-align: center;
            font-weight: 400;
            max-width: 700px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .mission-timeline {
            position: relative;
            max-width: 800px;
            margin: 0 auto;
        }
        
        .mission-timeline::before {
            content: '';
            position: absolute;
            left: 50%;
            top: 0;
            bottom: 0;
            width: 3px;
            background: linear-gradient(180deg, #8B1538 0%, #5D0E26 100%);
            transform: translateX(-50%);
        }
        
        .mission-item {
            position: relative;
            margin-bottom: 40px;
            width: 50%;
        }
        
        .mission-item:nth-child(odd) {
            left: 0;
            padding-right: 40px;
            text-align: right;
        }
        
        .mission-item:nth-child(even) {
            left: 50%;
            padding-left: 40px;
            text-align: left;
        }
        
        .mission-item::before {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            background: #8B1538;
            border-radius: 50%;
            top: 50%;
            transform: translateY(-50%);
            z-index: 2;
        }
        
        .mission-item:nth-child(odd)::before {
            right: -10px;
        }
        
        .mission-item:nth-child(even)::before {
            left: -10px;
        }
        
        .mission-item::after {
            content: '';
            position: absolute;
            width: 10px;
            height: 10px;
            background: white;
            border: 3px solid #8B1538;
            border-radius: 50%;
            top: 50%;
            transform: translateY(-50%);
            z-index: 3;
        }
        
        .mission-item:nth-child(odd)::after {
            right: -5px;
        }
        
        .mission-item:nth-child(even)::after {
            left: -5px;
        }
        
        .mission-card {
            background: white;
            padding: 30px 25px;
            border-radius: 15px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            border: 1px solid rgba(139, 21, 56, 0.1);
            transition: all 0.3s ease;
            position: relative;
        }
        
        .mission-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(139, 21, 56, 0.15);
        }
        
        .mission-card h3 {
            color: #8B1538;
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 15px;
            font-family: "Poppins", sans-serif;
        }
        
        .mission-card p {
            color: #666;
            font-size: 1rem;
            line-height: 1.6;
            margin: 0;
        }
        
        .team-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        
        .team-member {
            background: white;
            padding: 50px 40px;
            border-radius: 20px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: all 0.4s ease;
            border: 1px solid rgba(139, 21, 56, 0.1);
        }
        
        .team-member:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 50px rgba(139, 21, 56, 0.15);
            border-color: rgba(139, 21, 56, 0.3);
        }
        
        .team-member img {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            object-fit: cover;
            margin-bottom: 30px;
            border: 4px solid #8B1538;
            box-shadow: 0 10px 30px rgba(139, 21, 56, 0.3);
        }
        
        .team-member h3 {
            color: #333;
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 12px;
            font-family: "Poppins", sans-serif;
        }
        
        .team-member .position {
            color: #8B1538;
            font-size: 0.9rem;
            font-weight: 600;
            margin-bottom: 25px;
            text-transform: uppercase;
            letter-spacing: 1px;
            background: rgba(139, 21, 56, 0.1);
            padding: 10px 20px;
            border-radius: 25px;
            border: 1px solid rgba(139, 21, 56, 0.3);
            display: inline-block;
        }
        
        .team-member p {
            color: #666;
            font-size: 1rem;
            line-height: 1.7;
            margin: 0;
            text-align: center;
        }
        
        .values-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        
        .value-card {
            background: white;
            padding: 40px 30px;
            border-radius: 20px;
            border-left: 5px solid #8B1538;
            transition: all 0.4s ease;
            position: relative;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            border: 1px solid rgba(139, 21, 56, 0.1);
        }
        
        .value-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 50px rgba(139, 21, 56, 0.15);
            border-color: rgba(139, 21, 56, 0.3);
        }
        
        .value-card h3 {
            color: #333;
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 20px;
            font-family: "Poppins", sans-serif;
        }
        
        .value-card p {
            color: #666;
            font-size: 1rem;
            line-height: 1.7;
            margin: 0;
            text-align: left;
        }
        
        .contact-info {
            margin-top: 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
        }
        
        .contact-item {
            background: white;
            padding: 40px 30px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: all 0.4s ease;
            border: 1px solid rgba(139, 21, 56, 0.1);
            text-align: center;
        }
        
        .contact-item:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 50px rgba(139, 21, 56, 0.15);
            border-color: rgba(139, 21, 56, 0.3);
        }
        
        .contact-item i {
            font-size: 2.5rem;
            color: #8B1538;
            margin-bottom: 25px;
            display: block;
        }
        
        .contact-item h4 {
            color: #333;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 15px;
            font-family: "Poppins", sans-serif;
        }
        
        .contact-item p {
            color: #666;
            font-size: 1rem;
            margin: 0;
            line-height: 1.6;
        }
        
        /* Request Access Page Styles - Matching System Theme */
        .request-access-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 60vh;
            padding: 40px 20px;
        }
        
        .request-access-card {
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            border-radius: 24px;
            padding: 50px 40px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(93, 14, 38, 0.15);
            border: 2px solid rgba(93, 14, 38, 0.1);
            max-width: 500px;
            width: 100%;
        }
        
        .request-icon {
            font-size: 4rem;
            color: #5D0E26;
            margin-bottom: 20px;
        }
        
        .request-access-card h2 {
            color: #5D0E26;
            margin: 0 0 15px 0;
            font-size: 2rem;
            font-weight: 700;
            font-family: "Playfair Display", serif;
        }
        
        .request-access-card p {
            color: #666;
            margin: 0 0 30px 0;
            font-size: 1.1rem;
            line-height: 1.6;
        }
        
        .status-info {
            background: rgba(255, 255, 255, 0.8);
            border-radius: 16px;
            padding: 20px;
            margin: 20px 0;
            border: 2px solid;
        }
        
        .status-info.pending {
            border-color: #8B1538;
            background: linear-gradient(135deg, #fdf2f8 0%, #fce7f3 100%);
        }
        
        .status-info.rejected {
            border-color: #e74c3c;
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
        }
        
        .status-info i {
            font-size: 2rem;
            margin-bottom: 10px;
            display: block;
        }
        
        .status-info.pending i {
            color: #8B1538;
        }
        
        .status-info.rejected i {
            color: #e74c3c;
        }
        
        .status-info h3 {
            color: #5D0E26;
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 10px;
            font-family: "Playfair Display", serif;
        }
        
        .status-info p {
            color: #666;
            font-size: 1rem;
            margin-bottom: 0;
        }
        
        .rejection-details {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            border: 1px solid rgba(93, 14, 38, 0.2);
            text-align: left;
        }
        
        .rejection-details strong {
            color: #5D0E26;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        .rejection-notes {
            color: #666;
            font-size: 0.95rem;
            line-height: 1.5;
            margin: 0;
        }
        
        .request-actions {
            display: flex;
            flex-direction: column;
            gap: 15px;
            align-items: center;
        }
        
        .request-actions .btn {
            min-width: 200px;
            padding: 15px 30px;
            font-size: 1rem;
            font-weight: 600;
            border-radius: 12px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            transition: var(--transition);
            border: none;
            cursor: pointer;
        }
        
        .request-actions .btn-primary {
            background: var(--gradient-primary);
            color: white;
            box-shadow: 0 4px 15px rgba(93, 14, 38, 0.3);
        }
        
        .request-actions .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(93, 14, 38, 0.4);
        }
        
        .request-actions .btn-secondary {
            background: rgba(255, 255, 255, 0.9);
            color: #5D0E26;
            border: 2px solid rgba(93, 14, 38, 0.2);
        }
        
        .request-actions .btn-secondary:hover {
            background: rgba(93, 14, 38, 0.05);
            border-color: rgba(93, 14, 38, 0.3);
            color: #4A0B1E;
        }
        
        .request-actions .btn-success {
            background: var(--success-color);
            color: white;
            box-shadow: 0 4px 15px rgba(39, 174, 96, 0.3);
        }
        
        .request-actions .btn-success:hover {
            background: #229954;
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(39, 174, 96, 0.4);
        }
        
        .request-actions .btn-warning {
            background: var(--warning-color);
            color: white;
            box-shadow: 0 4px 15px rgba(243, 156, 18, 0.3);
        }
        
        .request-actions .btn-warning:hover {
            background: #e67e22;
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(243, 156, 18, 0.4);
        }
        
        .request-actions .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none !important;
            box-shadow: none !important;
        }
        
        .request-status-info {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 12px;
            padding: 15px 20px;
            margin-top: 15px;
            border: 1px solid rgba(93, 14, 38, 0.1);
            text-align: left;
        }
        
        .request-status-info small {
            color: #666;
            font-size: 0.9rem;
            line-height: 1.5;
        }
        
        .request-status-info strong {
            color: #5D0E26;
            font-weight: 600;
        }
        
        .request-status-info em {
            color: #666;
            font-style: italic;
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

        .sidebar {
            overflow-y: auto;
            scrollbar-width: none;
        }

        .sidebar::-webkit-scrollbar {
            display: none;
        }

        .sidebar.active .sidebar-close {
            display: flex;
        }

        .main-content {
            padding-top: 6px !important;
        }

        .main-content .header {
            margin-top: 0 !important;
        }

        /* Responsive Design */
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
                padding: 8px 16px;
                width: 100%;
                max-width: 100%;
                box-sizing: border-box;
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

            /* About page mobile styles */
            .about-hero {
                padding: 40px 20px;
                min-height: 200px;
            }

            .about-hero h1 {
                font-size: 1.8rem;
            }
            
            .about-hero p {
                font-size: 0.9rem;
            }

            .about-content {
                padding: 20px 16px;
            }
            
            .about-section {
                padding: 0;
                margin-bottom: 30px;
            }
            
            .about-section h2 {
                font-size: 1.4rem;
            }

            .about-section p {
                font-size: 0.95rem;
            }
            
            .story-section {
                grid-template-columns: 1fr;
                gap: 25px;
                padding: 20px 0;
            }

            .story-image {
                height: 250px;
            }
            
            .story-image img {
                height: 100%;
            }

            .story-content {
                padding: 20px 0;
            }

            .story-content h2 {
                font-size: 1rem;
                margin-bottom: 15px;
            }

            .story-content h3 {
                font-size: 1.8rem;
                margin-bottom: 20px;
            }

            .story-content p {
                font-size: 0.95rem;
                line-height: 1.6;
                margin-bottom: 20px;
            }

            .story-content .cta-button {
                padding: 12px 24px;
                font-size: 0.9rem;
            }

            .mission-intro {
                font-size: 1.1rem;
                margin-bottom: 40px;
            }

            .mission-timeline::before {
                left: 20px;
            }

            .mission-item {
                width: 100%;
                left: 0 !important;
                padding-left: 50px !important;
                padding-right: 0 !important;
                text-align: left !important;
                margin-bottom: 30px;
            }

            .mission-item::before {
                left: 11px !important;
                right: auto !important;
            }

            .mission-item::after {
                left: 16px !important;
                right: auto !important;
            }

            .mission-card {
                padding: 20px 18px;
            }

            .mission-card h3 {
                font-size: 1rem;
                margin-bottom: 12px;
            }

            .mission-card p {
                font-size: 0.9rem;
            }
            
            .team-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }

            .team-member {
                padding: 30px 20px;
            }

            .team-member img {
                width: 100px;
                height: 100px;
                margin-bottom: 20px;
            }

            .team-member h3 {
                font-size: 1.2rem;
            }

            .team-member .position {
                font-size: 0.8rem;
                padding: 8px 16px;
                margin-bottom: 20px;
            }

            .team-member p {
                font-size: 0.9rem;
            }
            
            .values-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }

            .value-card {
                padding: 25px 20px;
            }

            .value-card h3 {
                font-size: 1.2rem;
                margin-bottom: 15px;
            }

            .value-card p {
                font-size: 0.9rem;
            }
            
            .contact-info {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .contact-item {
                flex-direction: column;
                text-align: center;
                padding: 30px 20px;
            }

            .contact-item i {
                font-size: 2rem;
                margin-bottom: 20px;
            }

            .contact-item h4 {
                font-size: 1.1rem;
                margin-bottom: 12px;
            }

            .contact-item p {
                font-size: 0.9rem;
            }

            /* Request access card mobile */
            .request-access-card {
                padding: 30px 20px;
            }

            .request-icon {
                font-size: 3rem;
            }

            .request-access-card h2 {
                font-size: 1.6rem;
            }

            .request-access-card p {
                font-size: 1rem;
            }

            .request-actions .btn {
                min-width: auto;
                width: 100%;
                padding: 12px 24px;
                font-size: 0.95rem;
            }
        }

        @media (max-width: 480px) {
            .hamburger-menu {
                top: 4px;
                left: 4px;
                padding: 6px;
            }

            .hamburger-menu i {
                font-size: 1rem;
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
                padding-top: 16px !important;
            }

            /* Header ultra compact */
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
                width: 36px;
                height: 36px;
                margin-right: 8px;
            }

            /* About page ultra mobile */
            .about-hero {
                padding: 30px 16px;
                min-height: 180px;
            }

            .about-hero h1 {
                font-size: 1.5rem;
            }
            
            .about-hero p {
                font-size: 0.85rem;
            }

            .about-content {
                padding: 16px 12px;
            }

            .about-section {
                margin-bottom: 25px;
            }
            
            .about-section h2 {
                font-size: 1.2rem;
                margin-bottom: 20px;
            }

            .about-section p {
                font-size: 0.9rem;
            }

            .story-section {
                gap: 20px;
                padding: 16px 0;
            }

            .story-image {
                height: 200px;
                border-radius: 12px;
            }

            .story-content {
                padding: 16px 0;
            }

            .story-content h2 {
                font-size: 0.9rem;
                margin-bottom: 12px;
            }

            .story-content h3 {
                font-size: 1.5rem;
                margin-bottom: 16px;
            }

            .story-content p {
                font-size: 0.9rem;
                line-height: 1.5;
                margin-bottom: 16px;
            }

            .story-content .cta-button {
                padding: 10px 20px;
                font-size: 0.85rem;
            }

            .mission-intro {
                font-size: 1rem;
                margin-bottom: 30px;
            }

            .mission-item {
                padding-left: 45px !important;
                margin-bottom: 25px;
            }

            .mission-card {
                padding: 16px 14px;
            }

            .mission-card h3 {
                font-size: 0.95rem;
                margin-bottom: 10px;
            }

            .mission-card p {
                font-size: 0.85rem;
            }

            .team-grid {
                gap: 16px;
            }

            .team-member {
                padding: 25px 16px;
            }

            .team-member img {
                width: 90px;
                height: 90px;
                margin-bottom: 16px;
            }

            .team-member h3 {
                font-size: 1.1rem;
            }

            .team-member .position {
                font-size: 0.75rem;
                padding: 6px 12px;
                margin-bottom: 16px;
            }

            .team-member p {
                font-size: 0.85rem;
            }

            .values-grid {
                gap: 16px;
            }

            .value-card {
                padding: 20px 16px;
            }

            .value-card h3 {
                font-size: 1.1rem;
                margin-bottom: 12px;
            }

            .value-card p {
                font-size: 0.85rem;
            }

            .contact-info {
                gap: 16px;
            }

            .contact-item {
                padding: 25px 16px;
            }

            .contact-item i {
                font-size: 1.8rem;
                margin-bottom: 16px;
            }

            .contact-item h4 {
                font-size: 1rem;
                margin-bottom: 10px;
            }

            .contact-item p {
                font-size: 0.85rem;
            }

            /* Request access card ultra mobile */
            .request-access-card {
                padding: 25px 16px;
            }

            .request-icon {
                font-size: 2.5rem;
            }

            .request-access-card h2 {
                font-size: 1.4rem;
            }

            .request-access-card p {
                font-size: 0.9rem;
            }

            .request-actions .btn {
                padding: 10px 20px;
                font-size: 0.9rem;
            }

            .status-info {
                padding: 16px;
            }

            .status-info i {
                font-size: 1.8rem;
            }

            .status-info h3 {
                font-size: 1.1rem;
            }

            .status-info p {
                font-size: 0.9rem;
            }

            .rejection-details {
                padding: 16px;
            }

            .rejection-details strong {
                font-size: 0.85rem;
            }

            .rejection-notes {
                font-size: 0.9rem;
            }
        }

        @media (max-width: 360px) {
            .header h1 {
                font-size: 1rem !important;
            }

            .about-hero h1 {
                font-size: 1.3rem;
            }

            .story-content h3 {
                font-size: 1.3rem;
            }

            .about-section h2 {
                font-size: 1.1rem;
            }
        }

        /* Touch device optimizations */
        @media (hover: none) and (pointer: coarse) {
            .story-image:hover img {
                transform: none;
            }

            .team-member:hover,
            .value-card:hover,
            .contact-item:hover {
                transform: none;
            }

            .request-actions .btn {
                min-height: 44px;
                -webkit-tap-highlight-color: transparent;
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
                <a href="client_dashboard.php" title="View your case overview, statistics, and recent activities">
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
                <a href="client_about.php" class="active" title="Learn more about Opiña Law Office and our team">
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

    <!-- Main Content -->
    <div class="main-content">
        <!-- Header -->
        <?php 
        $page_title = 'About Us';
        $page_subtitle = 'Learn more about Opiña Law Office and our dedicated team';
        include 'components/profile_header.php'; 
        ?>

            <!-- About Us Content -->
            <div class="about-container">
                <!-- Hero Section -->
                <div class="about-hero">
                    <h1>About Opiña Law Office</h1>
                    <p>Dedicated to providing exceptional legal services with integrity, professionalism, and unwavering commitment to our clients' success.</p>
                </div>

                <div class="about-content">
                    <!-- Our Story Section -->
                    <div class="story-section">
                        <div class="story-image">
                            <img src="images/law-office-building.jpg" alt="Opiña Law Office Building" onerror="this.src='images/default-avatar.jpg'">
                        </div>
                        <div class="story-content">
                            <h2>About Us</h2>
                            <h3>We Always Provide The Best Legal Services</h3>
                            <p>Opiña Law Office was established with a vision to provide accessible, high-quality legal services to individuals and businesses throughout the Philippines. Founded on the principles of integrity, excellence, and client-centered service, our firm has grown to become a trusted partner in legal matters.</p>
                            <p>With years of experience in various areas of law, we have successfully represented countless clients, helping them navigate complex legal challenges and achieve favorable outcomes. Our commitment to staying current with legal developments and maintaining the highest ethical standards sets us apart in the legal community.</p>
                            <a href="client_messages.php" class="cta-button">Contact Us</a>
                        </div>
                    </div>

                    <!-- Our Mission Section -->
                    <div class="about-section">
                        <h2>Our Mission</h2>
                        <div class="mission-content">
                            <p class="mission-intro">To provide comprehensive, ethical, and effective legal representation that empowers our clients to make informed decisions and achieve their legal objectives.</p>
                            <div class="mission-timeline">
                                <div class="mission-item">
                                    <div class="mission-card">
                                        <h3>Personalized Solutions</h3>
                                        <p>Delivering tailored legal solutions that meet each client's unique needs and circumstances.</p>
                                    </div>
                                </div>
                                <div class="mission-item">
                                    <div class="mission-card">
                                        <h3>Professional Excellence</h3>
                                        <p>Maintaining the highest standards of professionalism and integrity in all our legal services.</p>
                                    </div>
                                </div>
                                <div class="mission-item">
                                    <div class="mission-card">
                                        <h3>Community Access</h3>
                                        <p>Ensuring accessibility to quality legal services for all members of our community.</p>
                                    </div>
                                </div>
                                <div class="mission-item">
                                    <div class="mission-card">
                                        <h3>Continuous Growth</h3>
                                        <p>Continuously improving our knowledge and skills to better serve our clients.</p>
                                    </div>
                                </div>
                                <div class="mission-item">
                                    <div class="mission-card">
                                        <h3>Trust & Respect</h3>
                                        <p>Building lasting relationships based on trust, respect, and mutual success.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Our Values Section -->
                    <div class="about-section">
                        <h2>Our Values</h2>
                        <div class="values-grid">
                            <div class="value-card">
                                <h3>Integrity</h3>
                                <p>We conduct ourselves with the highest ethical standards, ensuring transparency and honesty in all our interactions.</p>
                            </div>
                            <div class="value-card">
                                <h3>Client-Centered</h3>
                                <p>Our clients' interests and needs are at the heart of everything we do, guiding our decisions and strategies.</p>
                            </div>
                            <div class="value-card">
                                <h3>Excellence</h3>
                                <p>We strive for excellence in every aspect of our practice, from legal research to client communication.</p>
                            </div>
                            <div class="value-card">
                                <h3>Trust</h3>
                                <p>We build lasting relationships based on trust, reliability, and mutual respect with our clients and colleagues.</p>
                            </div>
                            <div class="value-card">
                                <h3>Innovation</h3>
                                <p>We embrace modern technology and innovative approaches to deliver efficient and effective legal services.</p>
                            </div>
                            <div class="value-card">
                                <h3>Community</h3>
                                <p>We are committed to serving our community and contributing to the betterment of society through our legal practice.</p>
                            </div>
                        </div>
                    </div>

                    <!-- Our Team Section -->
                    <div class="about-section">
                        <h2>Our Team</h2>
                        <p>Our team consists of highly qualified legal professionals who bring diverse expertise and a shared commitment to excellence. Each member of our team is dedicated to providing the highest quality legal services while maintaining the personal touch that our clients value.</p>
                        
                        <div class="team-grid">
                            <div class="team-member">
                                <img src="images/default-avatar.jpg" alt="Atty. Maria Opiña">
                                <h3>Atty. Maria Opiña</h3>
                                <div class="position">Managing Partner</div>
                                <p>With over 15 years of experience in civil and criminal law, Atty. Opiña leads our firm with dedication and expertise. She specializes in family law, property disputes, and corporate legal matters.</p>
                            </div>
                            <div class="team-member">
                                <img src="images/default-avatar.jpg" alt="Atty. Juan Santos">
                                <h3>Atty. Juan Santos</h3>
                                <div class="position">Senior Associate</div>
                                <p>Atty. Santos brings extensive experience in litigation and alternative dispute resolution. He is known for his strategic thinking and excellent courtroom advocacy skills.</p>
                            </div>
                            <div class="team-member">
                                <img src="images/default-avatar.jpg" alt="Atty. Ana Reyes">
                                <h3>Atty. Ana Reyes</h3>
                                <div class="position">Associate Attorney</div>
                                <p>Specializing in labor law and employment matters, Atty. Reyes provides comprehensive legal support to both employees and employers in various workplace issues.</p>
                            </div>
                        </div>
                    </div>

                    <!-- Contact Information Section -->
                    <div class="about-section">
                        <h2>Contact Information</h2>
                        <p>We are here to help you with your legal needs. Contact us today to schedule a consultation or learn more about our services.</p>
                        
                        <div class="contact-info">
                            <div class="contact-item">
                                <i class="fas fa-map-marker-alt"></i>
                                <h4>Office Address</h4>
                                <p>123 Legal Street, Barangay Justice<br>Quezon City, Metro Manila 1100<br>Philippines</p>
                            </div>
                            <div class="contact-item">
                                <i class="fas fa-phone"></i>
                                <h4>Phone Number</h4>
                                <p>+63 2 1234 5678<br>+63 917 123 4567</p>
                            </div>
                            <div class="contact-item">
                                <i class="fas fa-envelope"></i>
                                <h4>Email Address</h4>
                                <p>info@opinialaw.com<br>support@opinialaw.com</p>
                            </div>
                            <div class="contact-item">
                                <i class="fas fa-clock"></i>
                                <h4>Office Hours</h4>
                                <p>Monday - Friday: 8:00 AM - 6:00 PM<br>Saturday: 9:00 AM - 1:00 PM<br>Sunday: Closed</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
    </div>


    <script src="assets/js/modal-functions.js?v=<?= time() ?>"></script>
    
    <script>
        // Notifications functionality
        let notificationsVisible = false;

        // Close notifications when clicking outside
        document.addEventListener('click', function(event) {
            const notificationsBtn = document.getElementById('notificationsBtn');
            const dropdown = document.getElementById('notificationsDropdown');
            
            if (notificationsBtn && dropdown && !notificationsBtn.contains(event.target) && !dropdown.contains(event.target)) {
                dropdown.style.display = 'none';
                notificationsVisible = false;
            }
        });

        function loadNotifications() {
            fetch('get_notifications.php')
                .then(response => response.json())
                .then(data => {
                    updateNotificationBadge(data.unread_count);
                    displayNotifications(data.notifications);
                })
                .catch(error => console.error('Error loading notifications:', error));
        }

        function updateNotificationBadge(count) {
            const badge = document.getElementById('notificationBadge');
            if (count > 0) {
                badge.textContent = count > 99 ? '99+' : count;
                badge.style.display = 'flex';
            } else {
                badge.style.display = 'none';
            }
        }

        function displayNotifications(notifications) {
            const container = document.getElementById('notificationsList');
            
            if (notifications.length === 0) {
                container.innerHTML = '<div style="padding: 20px; text-align: center; color: #6b7280;">No notifications</div>';
                return;
            }
            
            container.innerHTML = notifications.map(notification => `
                <div style="padding: 12px; border-bottom: 1px solid #f3f4f6; ${!notification.is_read ? 'background: #f0f8ff;' : ''}">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div style="flex: 1;">
                            <div style="font-weight: 600; font-size: 14px; color: #1a202c; margin-bottom: 4px;">${notification.title}</div>
                            <div style="font-size: 12px; color: #6b7280; margin-bottom: 4px;">${notification.message}</div>
                            <div style="font-size: 11px; color: #9ca3af;">${formatTime(notification.created_at)}</div>
                        </div>
                        <div style="width: 8px; height: 8px; border-radius: 50%; background: ${getNotificationColor(notification.type)}; margin-left: 8px; ${notification.is_read ? 'display: none;' : ''}"></div>
                    </div>
                </div>
            `).join('');
        }

        function getNotificationColor(type) {
            switch (type) {
                case 'success': return '#10b981';
                case 'warning': return '#f59e0b';
                case 'error': return '#ef4444';
                default: return '#3b82f6';
            }
        }

        function formatTime(timestamp) {
            const date = new Date(timestamp);
            const now = new Date();
            const diff = now - date;
            
            if (diff < 60000) return 'Just now';
            if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
            if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
            return date.toLocaleDateString();
        }

        function markAllAsRead() {
            fetch('get_notifications.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'mark_read=true'
            })
            .then(() => {
                loadNotifications();
            })
            .catch(error => console.error('Error marking notifications as read:', error));
        }

        // Load notifications on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadNotifications();
            
            // Refresh notifications every 30 seconds
            setInterval(loadNotifications, 30000);
            
            // Notifications button click handler
            const notificationsBtn = document.getElementById('notificationsBtn');
            if (notificationsBtn) {
                notificationsBtn.addEventListener('click', function() {
                    const dropdown = document.getElementById('notificationsDropdown');
                    const isVisible = dropdown.style.display === 'block';
                    dropdown.style.display = isVisible ? 'none' : 'block';
                    
                    if (!isVisible) {
                        loadNotifications();
                    }
                });
            }
        });
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

<script src="assets/js/unread-messages.js?v=1761535513"></script></body>
</html>
