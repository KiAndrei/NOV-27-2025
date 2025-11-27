-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Nov 03, 2025 at 07:53 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `lawfirm`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin_messages`
--

CREATE TABLE `admin_messages` (
  `id` int(11) NOT NULL,
  `admin_id` int(11) NOT NULL,
  `recipient_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `sent_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `announcements`
--

CREATE TABLE `announcements` (
  `id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `image_path` varchar(500) DEFAULT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `announcements`
--

INSERT INTO `announcements` (`id`, `title`, `description`, `image_path`, `created_by`, `created_at`, `updated_at`) VALUES
(6, '', 'QWSDAD', 'uploads/announcements/announcement_2025-10-28_05-33-15_6900478b25acf.png', 94, '2025-10-28 04:33:15', '2025-10-28 04:33:15');

-- --------------------------------------------------------

--
-- Table structure for table `attorney_cases`
--

CREATE TABLE `attorney_cases` (
  `id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `attorney_id` int(11) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `client_id` int(11) DEFAULT NULL,
  `case_type` varchar(100) DEFAULT NULL,
  `status` varchar(50) DEFAULT 'Active',
  `next_hearing` date DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `attorney_documents`
--

CREATE TABLE `attorney_documents` (
  `id` int(11) NOT NULL,
  `file_size` bigint(20) DEFAULT NULL,
  `file_type` varchar(50) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `category` varchar(100) NOT NULL,
  `uploaded_by` int(11) NOT NULL,
  `upload_date` datetime NOT NULL DEFAULT current_timestamp(),
  `is_deleted` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `attorney_document_activity`
--

CREATE TABLE `attorney_document_activity` (
  `id` int(11) NOT NULL,
  `document_id` int(11) NOT NULL,
  `action` varchar(50) NOT NULL,
  `user_id` int(11) NOT NULL,
  `case_id` int(11) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `user_name` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `attorney_messages`
--

CREATE TABLE `attorney_messages` (
  `id` int(11) NOT NULL,
  `attorney_id` int(11) NOT NULL,
  `recipient_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `sent_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `audit_trail`
--

CREATE TABLE `audit_trail` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `user_name` varchar(100) NOT NULL,
  `user_type` enum('admin','attorney','client','employee') NOT NULL,
  `action` varchar(255) NOT NULL,
  `module` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `status` enum('success','failed','warning','info') DEFAULT 'success',
  `priority` enum('low','medium','high','critical') DEFAULT 'low',
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `additional_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`additional_data`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `audit_trail`
--

INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(11854, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:32:18', NULL),
(11855, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:32:35', NULL),
(11856, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:32:42', NULL),
(11857, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawd, dawd dwad (Doc #: 1, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 17:32:42', NULL),
(11858, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:32:42', NULL),
(11859, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:52:02', NULL),
(11860, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:52:07', NULL),
(11861, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:53:47', NULL),
(11862, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:53:53', NULL),
(11863, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 17:53:55', NULL),
(11864, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:00:51', NULL),
(11865, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:00:56', NULL),
(11866, 116, 'dawdw, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: dwadaw.pdf (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:00:56', NULL),
(11867, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:00:56', NULL),
(11868, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:02:49', NULL),
(11869, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:02:55', NULL),
(11870, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: qwe qwe 1.pdf (Doc #: 15, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:02:55', NULL),
(11871, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:02:55', NULL),
(11872, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:02:59', NULL),
(11873, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: asd asd a.pdf (Doc #: 16, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:02:59', NULL),
(11874, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:02:59', NULL),
(11875, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:03:11', NULL),
(11876, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawdw, dawd dawd (Doc #: 12, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:03:11', NULL),
(11877, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:03:11', NULL),
(11878, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:03:51', NULL),
(11879, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:03:58', NULL),
(11880, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: asd.pdf (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:03:58', NULL),
(11881, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:03:58', NULL),
(11882, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:21', NULL),
(11883, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:22', NULL),
(11884, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:24', NULL),
(11885, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:24', NULL),
(11886, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:24', NULL),
(11887, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:25', NULL),
(11888, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:25', NULL),
(11889, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:25', NULL),
(11890, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:55', NULL),
(11891, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:04:59', NULL),
(11892, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:02', NULL),
(11893, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:07', NULL),
(11894, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: asd.pdf (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:05:07', NULL),
(11895, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:07', NULL),
(11896, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:19', NULL),
(11897, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:20', NULL),
(11898, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:20', NULL),
(11899, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:24', NULL),
(11900, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawdaw.docx (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:05:24', NULL),
(11901, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:24', NULL),
(11902, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:30', NULL),
(11903, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawdwa.pdf (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:05:30', NULL),
(11904, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:05:30', NULL),
(11905, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:07:29', NULL),
(11906, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:07:47', NULL),
(11907, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawda 1.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-30 18:07:47', NULL),
(11908, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1760801595_0_adwad.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-30 18:07:47', NULL),
(11909, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:07:50', NULL),
(11910, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:05', NULL),
(11911, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: 1760801595_0_adwad.pdf (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:08:05', NULL),
(11912, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:05', NULL),
(11913, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:17', NULL),
(11914, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:26', NULL),
(11915, 116, 'dawdw, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-30 18:08:28', NULL),
(11916, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:31', NULL),
(11917, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:33', NULL),
(11918, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:46', NULL),
(11919, 116, 'dawdw, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: dawdwa.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-30 18:08:47', NULL),
(11920, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-30 18:08:47', NULL),
(11921, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:55:00', NULL),
(11922, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:55:01', NULL),
(11923, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:55:06', NULL),
(11924, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawda 1.pdf (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-31 01:55:06', NULL),
(11925, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:55:06', NULL),
(11926, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:55:15', NULL),
(11927, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:55:16', NULL),
(11928, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:56:12', NULL),
(11929, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:56:22', NULL),
(11930, 116, 'dawdw, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dwadaw.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 01:56:23', NULL),
(11931, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:56:25', NULL),
(11932, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:56:28', NULL),
(11933, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:56:31', NULL),
(11934, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dwadaw.docx (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-31 01:56:31', NULL),
(11935, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:56:31', NULL),
(11936, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 01:56:33', NULL),
(11937, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 02:20:51', NULL),
(11938, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 02:20:56', NULL),
(11939, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 02:20:57', NULL),
(11940, 116, 'dawdw, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 02:21:03', NULL),
(11941, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 02:21:08', NULL),
(11942, 116, 'dawdw, dawd dawd', 'attorney', 'User Logout', 'Authentication', 'User logged out successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 02:21:51', NULL),
(11943, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:39:13', NULL),
(11944, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:39:15', NULL),
(11945, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:39:52', NULL),
(11946, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761746557_0_dawd 1.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 03:39:53', NULL),
(11947, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 03:39:54', NULL),
(11948, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:42:47', NULL),
(11949, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:44:22', NULL),
(11950, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:45:05', NULL),
(11951, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:45:13', NULL),
(11952, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:45:17', NULL),
(11953, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:45:18', NULL),
(11954, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:45:18', NULL),
(11955, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:45:26', NULL),
(11956, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:47:11', NULL),
(11957, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:47:51', NULL),
(11958, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:48:30', NULL),
(11959, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.docx to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 03:48:32', NULL),
(11960, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawdawd.docx to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 03:48:33', NULL),
(11961, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:48:38', NULL),
(11962, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:55:41', NULL),
(11963, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:55:44', NULL),
(11964, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:56:12', NULL),
(11965, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawda 1.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 03:56:12', NULL),
(11966, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1760801595_0_adwad.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 03:56:13', NULL),
(11967, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:56:13', NULL),
(11968, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:59:23', NULL),
(11969, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:59:27', NULL),
(11970, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawda 1.pdf (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-31 03:59:27', NULL),
(11971, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 03:59:27', NULL),
(11972, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:00:53', NULL),
(11973, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:00:54', NULL),
(11974, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:00:55', NULL),
(11975, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:01:12', NULL),
(11976, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.docx to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:01:16', NULL),
(11977, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:01:16', NULL),
(11978, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:05:03', NULL),
(11979, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:05:25', NULL),
(11980, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: REFREA_MIDTERM-SPA.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:05:25', NULL),
(11981, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawda 1.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:05:25', NULL),
(11982, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:07:44', NULL),
(11983, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:07:47', NULL),
(11984, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:07:48', NULL),
(11985, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:08:03', NULL),
(11986, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761746557_0_dawd 1.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:08:04', NULL),
(11987, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:08:05', NULL),
(11988, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:18', NULL),
(11989, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:19', NULL),
(11990, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:19', NULL),
(11991, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:34', NULL),
(11992, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:10:38', NULL),
(11993, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:40', NULL),
(11994, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:52', NULL),
(11995, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:56', NULL),
(11996, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:10:57', NULL),
(11997, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:11:29', NULL),
(11998, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:11:40', NULL),
(11999, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:11:42', NULL),
(12000, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawda 1.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:11:42', NULL),
(12001, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:11:44', NULL),
(12002, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:11:51', NULL),
(12003, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: 1761728229_0_dawdaw 2.docx (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-31 04:11:51', NULL),
(12004, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:11:51', NULL),
(12005, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:11:56', NULL),
(12006, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: 1761746557_0_dawd 1.docx (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-31 04:11:56', NULL),
(12007, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:11:56', NULL),
(12008, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:04', NULL),
(12009, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawda 1 (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:12:04', NULL),
(12010, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:04', NULL),
(12011, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:12', NULL),
(12012, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: 1761728229_0_dawdaw 2.docx (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'high', '2025-10-31 04:12:12', NULL),
(12013, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:12', NULL),
(12014, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:19', NULL),
(12015, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: 1761728229_0_dawdaw 2 (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:12:19', NULL),
(12016, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:19', NULL),
(12017, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:38', NULL),
(12018, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dasdawdwa (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:12:38', NULL),
(12019, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:38', NULL),
(12020, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:47', NULL),
(12021, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawdawdaw (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:12:47', NULL),
(12022, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:12:47', NULL),
(12023, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:00', NULL),
(12024, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawdwa (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:13:00', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(12025, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:00', NULL),
(12026, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:17', NULL),
(12027, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawda 1dawdaw (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:13:17', NULL),
(12028, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:17', NULL),
(12029, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:29', NULL),
(12030, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: REFREA_MIDTERM-SPAdawdawda (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:13:29', NULL),
(12031, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:29', NULL),
(12032, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:35', NULL),
(12033, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:35', NULL),
(12034, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:42', NULL),
(12035, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:48', NULL),
(12036, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:57', NULL),
(12037, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: asd, as as1 (Doc #: 2, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:13:57', NULL),
(12038, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:13:57', NULL),
(12039, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:14:11', NULL),
(12040, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: asd, as as1 (Doc #: 10, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:14:11', NULL),
(12041, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:14:11', NULL),
(12042, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:14:21', NULL),
(12043, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawdww, dawd dawd (Doc #: 3, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:14:22', NULL),
(12044, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:14:22', NULL),
(12045, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:14:34', NULL),
(12046, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawdww, dawd dawd (Doc #: 3, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:14:34', NULL),
(12047, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:14:34', NULL),
(12048, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:14:40', NULL),
(12049, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:15:10', NULL),
(12050, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:15:36', NULL),
(12051, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:17:22', NULL),
(12052, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:17:30', NULL),
(12053, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:19:38', NULL),
(12054, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:21:42', NULL),
(12055, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:21:53', NULL),
(12056, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:21:57', NULL),
(12057, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:21:58', NULL),
(12058, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:21:59', NULL),
(12059, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:22:08', NULL),
(12060, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:22:25', NULL),
(12061, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:22:41', NULL),
(12062, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:23:19', NULL),
(12063, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:25:04', NULL),
(12064, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:25:08', NULL),
(12065, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:25:13', NULL),
(12066, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:25:21', NULL),
(12067, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawda 1dawdaw (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:25:21', NULL),
(12068, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:25:21', NULL),
(12069, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:32:03', NULL),
(12070, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:32:10', NULL),
(12071, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:32:30', NULL),
(12072, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:32:55', NULL),
(12073, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:33:14', NULL),
(12074, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:33:19', NULL),
(12075, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:33:21', NULL),
(12076, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:33:40', NULL),
(12077, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:54:32', NULL),
(12078, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:54:36', NULL),
(12079, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:54:36', NULL),
(12080, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:54:51', NULL),
(12081, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761746557_0_dawd 1.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:54:52', NULL),
(12082, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawda 1.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 04:54:52', NULL),
(12083, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:54:52', NULL),
(12084, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:56:17', NULL),
(12085, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:56:35', NULL),
(12086, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:59:48', NULL),
(12087, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 04:59:56', NULL),
(12088, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:00:01', NULL),
(12089, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:00:02', NULL),
(12090, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:00:06', NULL),
(12091, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:02:33', NULL),
(12092, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:02:51', NULL),
(12093, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:02:54', NULL),
(12094, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:02:56', NULL),
(12095, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:00', NULL),
(12096, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:02', NULL),
(12097, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:03', NULL),
(12098, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:07', NULL),
(12099, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:08', NULL),
(12100, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:09', NULL),
(12101, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:10', NULL),
(12102, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:14', NULL),
(12103, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:03:15', NULL),
(12104, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:04:17', NULL),
(12105, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:04:30', NULL),
(12106, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dwadaw.pdf to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:04:30', NULL),
(12107, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:04:30', NULL),
(12108, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:04:38', NULL),
(12109, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawdww, dawd dawd (Doc #: 2, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:04:39', NULL),
(12110, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:04:39', NULL),
(12111, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:04:54', NULL),
(12112, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:04:59', NULL),
(12113, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:04:59', NULL),
(12114, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:05:11', NULL),
(12115, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:12:51', NULL),
(12116, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:12:52', NULL),
(12117, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:12:58', NULL),
(12118, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawda 1.pdf (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:12:58', NULL),
(12119, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:12:58', NULL),
(12120, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:13:06', NULL),
(12121, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawda 1.pdf (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:13:06', NULL),
(12122, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:13:06', NULL),
(12123, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:13:17', NULL),
(12124, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawdwa (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:13:17', NULL),
(12125, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:13:17', NULL),
(12126, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:16:28', NULL),
(12127, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:16:34', NULL),
(12128, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:16:35', NULL),
(12129, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:21:46', NULL),
(12130, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:22:01', NULL),
(12131, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:22:02', NULL),
(12132, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: REFREA_MIDTERM-SPA.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:22:02', NULL),
(12133, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:22:02', NULL),
(12134, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:28:27', NULL),
(12135, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:28:30', NULL),
(12136, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:28:31', NULL),
(12137, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:28:40', NULL),
(12138, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 3.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:28:42', NULL),
(12139, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:28:44', NULL),
(12140, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:31:58', NULL),
(12141, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:32:26', NULL),
(12142, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:32:42', NULL),
(12143, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:32:43', NULL),
(12144, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw dawdaw dawdwa2.pdf to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 05:32:43', NULL),
(12145, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:32:45', NULL),
(12146, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:03', NULL),
(12147, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:04', NULL),
(12148, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:05', NULL),
(12149, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:06', NULL),
(12150, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:07', NULL),
(12151, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:07', NULL),
(12152, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:32', NULL),
(12153, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:33', NULL),
(12154, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:34', NULL),
(12155, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:33:53', NULL),
(12156, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:03', NULL),
(12157, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:06', NULL),
(12158, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:30', NULL),
(12159, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:51', NULL),
(12160, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:52', NULL),
(12161, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:53', NULL),
(12162, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:54', NULL),
(12163, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:57', NULL),
(12164, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:34:57', NULL),
(12165, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:35:39', NULL),
(12166, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:35:45', NULL),
(12167, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:35:51', NULL),
(12168, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:03', NULL),
(12169, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:04', NULL),
(12170, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:05', NULL),
(12171, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:08', NULL),
(12172, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:08', NULL),
(12173, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:09', NULL),
(12174, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:10', NULL),
(12175, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:14', NULL),
(12176, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:36:49', NULL),
(12177, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:37:09', NULL),
(12178, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:37:23', NULL),
(12179, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:37:26', NULL),
(12180, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:37:32', NULL),
(12181, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:37:35', NULL),
(12182, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:38:05', NULL),
(12183, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:38:49', NULL),
(12184, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:38:51', NULL),
(12185, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:38:53', NULL),
(12186, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:41:15', NULL),
(12187, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:41:40', NULL),
(12188, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:41:42', NULL),
(12189, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:41:48', NULL),
(12190, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:41:54', NULL),
(12191, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:42:09', NULL),
(12192, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:42:35', NULL),
(12193, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:42:35', NULL),
(12194, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:42:49', NULL),
(12195, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:43:03', NULL),
(12196, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:43:03', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(12197, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:43:07', NULL),
(12198, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:43:12', NULL),
(12199, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:43:12', NULL),
(12200, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:43:18', NULL),
(12201, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:43:19', NULL),
(12202, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:45:13', NULL),
(12203, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:45:14', NULL),
(12204, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 05:45:23', NULL),
(12205, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:01:50', NULL),
(12206, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:01:51', NULL),
(12207, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:01:55', NULL),
(12208, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:01:56', NULL),
(12209, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:01:57', NULL),
(12210, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:01:59', NULL),
(12211, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:02:00', NULL),
(12212, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 06:02:02', NULL),
(12213, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 13:49:43', NULL),
(12214, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 13:54:55', NULL),
(12215, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: add_user', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 13:55:37', NULL),
(12216, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'User Create', 'User Management', 'Created new employee account: Nerfy, Yuhan Santiago (yuhanerfy@gmail.com) - Email sent successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 13:55:41', NULL),
(12217, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 13:55:42', NULL),
(12218, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 13:55:45', NULL),
(12219, 118, 'Nerfy, Yuhan Santiago', 'employee', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 13:55:57', NULL),
(12220, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:09:50', NULL),
(12221, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:09:51', NULL),
(12222, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:09:52', NULL),
(12223, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:09:57', NULL),
(12224, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:09:58', NULL),
(12225, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:04', NULL),
(12226, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:05', NULL),
(12227, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:06', NULL),
(12228, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:06', NULL),
(12229, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:07', NULL),
(12230, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:12', NULL),
(12231, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:19', NULL),
(12232, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:20', NULL),
(12233, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:10:20', NULL),
(12234, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:41:04', NULL),
(12235, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:42:33', NULL),
(12236, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:48:00', NULL),
(12237, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:48:06', NULL),
(12238, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:48:12', NULL),
(12239, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:48:33', NULL),
(12240, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:48:36', NULL),
(12241, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:48:37', NULL),
(12242, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 14:48:39', NULL),
(12243, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Password Change', 'Security', 'User changed password via email verification', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 15:00:50', NULL),
(12244, 118, 'Nerfy, Yuhan Santiago', 'employee', 'User Logout', 'Authentication', 'User logged out successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:00:53', NULL),
(12245, 0, 'System', '', 'Failed Login Attempt', 'Security', 'Failed login attempt for email: yuhanerfy@gmail.com (Attempt 1/4)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'failed', 'medium', '2025-10-31 15:01:12', NULL),
(12246, 118, 'Nerfy, Yuhan Santiago', 'employee', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:01:19', NULL),
(12247, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:07:04', NULL),
(12248, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:07:07', NULL),
(12249, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: add_user', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:07:35', NULL),
(12250, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'User Create', 'User Management', 'Created new attorney account: dawd, dawd dawd (marjohnrefrea1215@gmail.com) - Email sent successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 15:07:40', NULL),
(12251, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:07:40', NULL),
(12252, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:07:43', NULL),
(12253, 119, 'dawd, dawd dawd', 'attorney', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:08:04', NULL),
(12254, 119, 'dawd, dawd dawd', 'attorney', 'Password Change', 'Security', 'User changed password via email verification', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 15:08:43', NULL),
(12255, 119, 'dawd, dawd dawd', 'attorney', 'User Logout', 'Authentication', 'User logged out successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:08:46', NULL),
(12256, 119, 'dawd, dawd dawd', 'attorney', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:09:00', NULL),
(12257, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:12:24', NULL),
(12258, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:12:29', NULL),
(12259, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:12:32', NULL),
(12260, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:14:12', NULL),
(12261, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:14:14', NULL),
(12262, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:14:17', NULL),
(12263, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:14:23', NULL),
(12264, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:14:53', NULL),
(12265, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:19:48', NULL),
(12266, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:20:47', NULL),
(12267, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:22:01', NULL),
(12268, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:22:26', NULL),
(12269, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:05', NULL),
(12270, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:07', NULL),
(12271, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:08', NULL),
(12272, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:10', NULL),
(12273, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:11', NULL),
(12274, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:12', NULL),
(12275, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:13', NULL),
(12276, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:38', NULL),
(12277, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:26:55', NULL),
(12278, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:27:26', NULL),
(12279, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Client Create', 'Client Management', 'Created new client account: dawdaw, dadaw dawd (marjohnrefrea123456@gmail.com) - Email sent successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 15:27:57', NULL),
(12280, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:29:02', NULL),
(12281, 120, 'dawdaw, dadaw dawd', 'client', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:29:19', NULL),
(12282, 120, 'dawdaw, dadaw dawd', 'client', 'Password Change', 'Security', 'User changed password via email verification', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 15:30:30', NULL),
(12283, 120, 'dawdaw, dadaw dawd', 'client', 'User Logout', 'Authentication', 'User logged out successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:30:33', NULL),
(12284, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:34:47', NULL),
(12285, 120, 'dawdaw, dadaw dawd', 'client', 'User Login', 'Authentication', 'User logged in successfully', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:35:00', NULL),
(12286, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:47:25', NULL),
(12287, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:47:31', NULL),
(12288, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:47:32', NULL),
(12289, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:47:33', NULL),
(12290, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:52:59', NULL),
(12291, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:53:21', NULL),
(12292, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:53:27', NULL),
(12293, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:03', NULL),
(12294, 120, 'dawdaw, dadaw dawd', 'client', 'Request Form Submission', 'Communication', 'Submitted messaging request form with ID: REQ-20251031-0120-5400', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 15:54:03', NULL),
(12295, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:03', NULL),
(12296, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:05', NULL),
(12297, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:07', NULL),
(12298, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:20', NULL),
(12299, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:27', NULL),
(12300, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:31', NULL),
(12301, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:54', NULL),
(12302, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Request Review', 'Communication', 'Request ID: 57 - Action: Rejected', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 15:54:54', NULL),
(12303, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:54:54', NULL),
(12304, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:55:13', NULL),
(12305, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:55:28', NULL),
(12306, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 15:57:44', NULL),
(12307, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:01:28', NULL),
(12308, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:24', NULL),
(12309, 120, 'dawdaw, dadaw dawd', 'client', 'Request Form Submission', 'Communication', 'Submitted messaging request form with ID: REQ-20251031-0120-2347', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:02:24', NULL),
(12310, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:24', NULL),
(12311, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:25', NULL),
(12312, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:35', NULL),
(12313, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:37', NULL),
(12314, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:39', NULL),
(12315, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:41', NULL),
(12316, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:42', NULL),
(12317, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_send_files', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:43', NULL),
(12318, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_send_files', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:46', NULL),
(12319, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:47', NULL),
(12320, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:53', NULL),
(12321, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:56', NULL),
(12322, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Request Review', 'Communication', 'Request ID: 58 - Action: Rejected', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:02:56', NULL),
(12323, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:02:56', NULL),
(12324, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:03:01', NULL),
(12325, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:03:03', NULL),
(12326, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:03:11', NULL),
(12327, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:04:50', NULL),
(12328, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:10', NULL),
(12329, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:13', NULL),
(12330, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:24', NULL),
(12331, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:25', NULL),
(12332, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:25', NULL),
(12333, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:25', NULL),
(12334, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:25', NULL),
(12335, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:51', NULL),
(12336, 120, 'dawdaw, dadaw dawd', 'client', 'Request Form Submission', 'Communication', 'Submitted messaging request form with ID: REQ-20251031-0120-4394', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:05:51', NULL),
(12337, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:51', NULL),
(12338, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:52', NULL),
(12339, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:53', NULL),
(12340, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:58', NULL),
(12341, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Request Review', 'Communication', 'Request ID: 59 - Action: Rejected', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:05:58', NULL),
(12342, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:05:58', NULL),
(12343, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:06:01', NULL),
(12344, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:06:04', NULL),
(12345, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:06:11', NULL),
(12346, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:06:12', NULL),
(12347, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:06:12', NULL),
(12348, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:06:12', NULL),
(12349, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:19', NULL),
(12350, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:22', NULL),
(12351, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:47', NULL),
(12352, 120, 'dawdaw, dadaw dawd', 'client', 'Request Form Submission', 'Communication', 'Submitted messaging request form with ID: REQ-20251031-0120-4576', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:08:47', NULL),
(12353, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:47', NULL),
(12354, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:47', NULL),
(12355, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:48', NULL),
(12356, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:51', NULL),
(12357, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:54', NULL),
(12358, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Request Review', 'Communication', 'Request ID: 60 - Action: Rejected', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:08:54', NULL),
(12359, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:54', NULL),
(12360, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:08:56', NULL),
(12361, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:09:01', NULL),
(12362, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:09:57', NULL),
(12363, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:02', NULL),
(12364, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:25', NULL),
(12365, 120, 'dawdaw, dadaw dawd', 'client', 'Request Form Submission', 'Communication', 'Submitted messaging request form with ID: REQ-20251031-0120-5882', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:10:25', NULL),
(12366, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_request_access', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:26', NULL),
(12367, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:26', NULL),
(12368, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:28', NULL),
(12369, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:31', NULL),
(12370, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Request Review', 'Communication', 'Request ID: 61 - Action: Rejected', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:10:31', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(12371, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:31', NULL),
(12372, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:34', NULL),
(12373, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:47', NULL),
(12374, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:50', NULL),
(12375, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:51', NULL),
(12376, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:53', NULL),
(12377, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:53', NULL),
(12378, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:57', NULL),
(12379, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:58', NULL),
(12380, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:10:59', NULL),
(12381, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:11:59', NULL),
(12382, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:12', NULL),
(12383, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:14', NULL),
(12384, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:15', NULL),
(12385, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:16', NULL),
(12386, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:17', NULL),
(12387, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:19', NULL),
(12388, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:21', NULL),
(12389, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:23', NULL),
(12390, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:26', NULL),
(12391, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:12:58', NULL),
(12392, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:00', NULL),
(12393, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:03', NULL),
(12394, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:05', NULL),
(12395, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:20', NULL),
(12396, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:22', NULL),
(12397, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:22', NULL),
(12398, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:23', NULL),
(12399, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:26', NULL),
(12400, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_send_files', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:35', NULL),
(12401, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_send_files', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:37', NULL),
(12402, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_send_files', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:44', NULL),
(12403, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:13:54', NULL),
(12404, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:22', NULL),
(12405, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:33', NULL),
(12406, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:35', NULL),
(12407, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw dawdaw dadwa2.docx (Category: Notarized Documents, Doc #: 21, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:14:36', NULL),
(12408, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dadaw dawda dadw.pdf (Category: Notarized Documents, Doc #: 112, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:14:36', NULL),
(12409, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:38', NULL),
(12410, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:43', NULL),
(12411, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdaw, dawdaw dawdwa2 (Category: Notarized Documents, Doc #: 1, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:14:43', NULL),
(12412, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:43', NULL),
(12413, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:45', NULL),
(12414, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdaw, dawdaw dawdwa2 (Category: Notarized Documents, Doc #: 1, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:14:45', NULL),
(12415, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:14:45', NULL),
(12416, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:19', NULL),
(12417, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:23', NULL),
(12418, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdawd, dadawd dawd (Category: Notarized Documents, Doc #: 3, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:19:23', NULL),
(12419, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:23', NULL),
(12420, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:25', NULL),
(12421, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdawd, dadawd dawd (Category: Notarized Documents, Doc #: 3, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:19:25', NULL),
(12422, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:25', NULL),
(12423, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:32', NULL),
(12424, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdawd, dadawd dawd.pdf (Category: Notarized Documents, Doc #: 3, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:19:32', NULL),
(12425, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:32', NULL),
(12426, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:34', NULL),
(12427, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:44', NULL),
(12428, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: ASD, ASD ASDD (Category: Notarized Documents, Doc #: 10, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:19:44', NULL),
(12429, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:44', NULL),
(12430, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:46', NULL),
(12431, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:50', NULL),
(12432, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: ASD, ASD ASDD.pdf (Category: Notarized Documents, Doc #: 10, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:19:50', NULL),
(12433, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:50', NULL),
(12434, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:52', NULL),
(12435, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:19:59', NULL),
(12436, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:20:01', NULL),
(12437, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdww, dawd dawd (Category: Notarized Documents, Doc #: 2, Book #: 10)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-10-31 16:20:01', NULL),
(12438, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:20:01', NULL),
(12439, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-10-31 16:20:04', NULL),
(12440, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:37:09', NULL),
(12441, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:37:10', NULL),
(12442, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:37:30', NULL),
(12443, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:37:45', NULL),
(12444, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: DAWDAW.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:37:46', NULL),
(12445, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: DAWDAW.pdf (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:37:46', NULL),
(12446, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:37:56', NULL),
(12447, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:39:51', NULL),
(12448, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: DAWDAW (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:39:52', NULL),
(12449, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:39:52', NULL),
(12450, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:39:56', NULL),
(12451, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: DAWDAW (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:39:56', NULL),
(12452, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:39:56', NULL),
(12453, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:01', NULL),
(12454, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:01', NULL),
(12455, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:01', NULL),
(12456, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:03', NULL),
(12457, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:18', NULL),
(12458, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761747143_0_dawdaw 1.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:55:19', NULL),
(12459, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761746557_0_dawd.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:55:19', NULL),
(12460, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:21', NULL),
(12461, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:29', NULL),
(12462, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: 1761746557_0_dawd (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:55:29', NULL),
(12463, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:29', NULL),
(12464, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:41', NULL),
(12465, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: DAWDAW (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 04:55:41', NULL),
(12466, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:55:41', NULL),
(12467, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 04:57:03', NULL),
(12468, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:02:49', NULL),
(12469, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:02:54', NULL),
(12470, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: REFREA_MIDTERM-SPA.pdf (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:02:54', NULL),
(12471, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:02:54', NULL),
(12472, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:03:03', NULL),
(12473, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: w.pdf (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:03:03', NULL),
(12474, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:03:03', NULL),
(12475, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:03:19', NULL),
(12476, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawdawd, dadawd dawd.pdf.pdf (Doc #: 3, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:03:19', NULL),
(12477, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:03:19', NULL),
(12478, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:03:23', NULL),
(12479, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawdww, dawd dawd (Doc #: 2, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:03:23', NULL),
(12480, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:03:23', NULL),
(12481, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:04:18', NULL),
(12482, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:04:26', NULL),
(12483, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:04:30', NULL),
(12484, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:04:52', NULL),
(12485, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dwadaw.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:04:53', NULL),
(12486, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:04:54', NULL),
(12487, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:00', NULL),
(12488, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: dwadaw.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:05:00', NULL),
(12489, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:00', NULL),
(12490, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:05', NULL),
(12491, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: dwadawdawdaw.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:05:05', NULL),
(12492, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:05', NULL),
(12493, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:10', NULL),
(12494, 119, 'dawd, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: DAWDAW (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-02 05:05:10', NULL),
(12495, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:10', NULL),
(12496, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:12', NULL),
(12497, 119, 'dawd, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: DAWDAW (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-02 05:05:12', NULL),
(12498, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:12', NULL),
(12499, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:50', NULL),
(12500, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.docx (Category: Law Office Files, Doc #: 0, Book #: 0)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:05:51', NULL),
(12501, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawd dadw dawd.pdf (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:05:51', NULL),
(12502, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:05:53', NULL),
(12503, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:07:08', NULL),
(12504, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:07:20', NULL),
(12505, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:07:32', NULL),
(12506, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:07:33', NULL),
(12507, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: WEEK 9-10 Mendoza Miranda Refrea Sarino Soriano.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:07:33', NULL),
(12508, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:07:35', NULL),
(12509, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:08:03', NULL),
(12510, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dadwa dad dadw.docx to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:08:04', NULL),
(12511, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawwa dawdaw dawd.pdf to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:08:04', NULL),
(12512, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:08:08', NULL),
(12513, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:08:29', NULL),
(12514, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dadwa, dad dadw.docx (Doc #: 1212, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:08:29', NULL),
(12515, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:08:29', NULL),
(12516, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:09:59', NULL),
(12517, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawdawd, dadawd dawd.pdf.pdf (Doc #: 3, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-02 05:09:59', NULL),
(12518, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:09:59', NULL),
(12519, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:03', NULL),
(12520, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: adwwad, dawd dawdawd.docx (Doc #: 4, Book #: 10, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:10:03', NULL),
(12521, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:03', NULL),
(12522, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:25', NULL),
(12523, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:30', NULL),
(12524, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawwa, dawdaw dawd.pdf (Category: Notarized Documents, Doc #: 123, Book #: 1)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:10:30', NULL),
(12525, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:30', NULL),
(12526, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:32', NULL),
(12527, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:42', NULL),
(12528, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dadwa, dad dadw.docx (Category: Notarized Documents, Doc #: 1212, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:10:42', NULL),
(12529, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:42', NULL),
(12530, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:44', NULL),
(12531, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:54', NULL),
(12532, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:10:56', NULL),
(12533, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:17:35', NULL),
(12534, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:18:04', NULL),
(12535, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:19:26', NULL),
(12536, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:26:28', NULL),
(12537, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:26:32', NULL),
(12538, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:26:51', NULL),
(12539, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dasdas.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:26:51', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(12540, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:26:53', NULL),
(12541, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:27:00', NULL),
(12542, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: dasdas.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:27:00', NULL),
(12543, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:27:00', NULL),
(12544, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:30:35', NULL),
(12545, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:32:29', NULL),
(12546, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:34:10', NULL),
(12547, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:34:21', NULL),
(12548, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:35:53', NULL),
(12549, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:43:07', NULL),
(12550, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:44:55', NULL),
(12551, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:26', NULL),
(12552, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawdwadaw.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:45:27', NULL),
(12553, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dwawa.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:45:27', NULL),
(12554, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:29', NULL),
(12555, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:35', NULL),
(12556, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dawdwadaw.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:45:35', NULL),
(12557, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:35', NULL),
(12558, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:40', NULL),
(12559, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:42', NULL),
(12560, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:43', NULL),
(12561, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:45:58', NULL),
(12562, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:46:37', NULL),
(12563, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw dawdwa dawdwa.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:46:38', NULL),
(12564, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:46:38', NULL),
(12565, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:46:40', NULL),
(12566, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:46:45', NULL),
(12567, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:46:45', NULL),
(12568, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:46:47', NULL),
(12569, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:04', NULL),
(12570, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:04', NULL),
(12571, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:06', NULL),
(12572, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:09', NULL),
(12573, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:34', NULL),
(12574, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa wdawdaw dadw.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 05:47:34', NULL),
(12575, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:36', NULL),
(12576, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:40', NULL),
(12577, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:44', NULL),
(12578, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:46', NULL),
(12579, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:48', NULL),
(12580, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:50', NULL),
(12581, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:52', NULL),
(12582, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 05:47:54', NULL),
(12583, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:03:55', NULL),
(12584, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:04:00', NULL),
(12585, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:04:16', NULL),
(12586, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:04:18', NULL),
(12587, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:04:20', NULL),
(12588, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:05:34', NULL),
(12589, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:06:25', NULL),
(12590, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:06:36', NULL),
(12591, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:06:51', NULL),
(12592, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:06:59', NULL),
(12593, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Delete', 'Document Management', 'Deleted document: dawdaw, dawdwa dawdwa (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-02 06:06:59', NULL),
(12594, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:06:59', NULL),
(12595, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:07:15', NULL),
(12596, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:07:33', NULL),
(12597, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:07:49', NULL),
(12598, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:07:50', NULL),
(12599, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:22:33', NULL),
(12600, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:36:14', NULL),
(12601, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:36:17', NULL),
(12602, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:36:19', NULL),
(12603, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:36:27', NULL),
(12604, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:36:27', NULL),
(12605, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:36:29', NULL),
(12606, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:01', NULL),
(12607, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:03', NULL),
(12608, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, wdawdaw dadw.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:37:03', NULL),
(12609, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:03', NULL),
(12610, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:05', NULL),
(12611, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:06', NULL),
(12612, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:07', NULL),
(12613, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:37:07', NULL),
(12614, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:07', NULL),
(12615, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:08', NULL),
(12616, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:37:09', NULL),
(12617, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:47:39', NULL),
(12618, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:47:41', NULL),
(12619, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:47:41', NULL),
(12620, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:47:43', NULL),
(12621, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:47:45', NULL),
(12622, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:47:45', NULL),
(12623, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:47:47', NULL),
(12624, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:48:07', NULL),
(12625, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:48:09', NULL),
(12626, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:48:09', NULL),
(12627, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:48:09', NULL),
(12628, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:48:11', NULL),
(12629, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:15', NULL),
(12630, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:19', NULL),
(12631, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:22', NULL),
(12632, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:49:22', NULL),
(12633, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:22', NULL),
(12634, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:23', NULL),
(12635, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:29', NULL),
(12636, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:31', NULL),
(12637, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:49:31', NULL),
(12638, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:31', NULL),
(12639, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:33', NULL),
(12640, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:54', NULL),
(12641, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:56', NULL),
(12642, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:49:56', NULL),
(12643, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:56', NULL),
(12644, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:49:57', NULL),
(12645, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:50:28', NULL),
(12646, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:51:21', NULL),
(12647, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:51:28', NULL),
(12648, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:51:28', NULL),
(12649, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:51:30', NULL),
(12650, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:06', NULL),
(12651, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:20', NULL),
(12652, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:26', NULL),
(12653, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:35', NULL),
(12654, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdwa, dawdaw dawaw.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:56:35', NULL),
(12655, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:35', NULL),
(12656, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:45', NULL),
(12657, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: daw.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:56:45', NULL),
(12658, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:45', NULL),
(12659, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:56', NULL),
(12660, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dwdw.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:56:56', NULL),
(12661, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:56:56', NULL),
(12662, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:57:05', NULL),
(12663, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dww.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 06:57:05', NULL),
(12664, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:57:05', NULL),
(12665, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:57:13', NULL),
(12666, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:57:19', NULL),
(12667, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:57:19', NULL),
(12668, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:57:30', NULL),
(12669, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:58:45', NULL),
(12670, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:58:50', NULL),
(12671, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 06:59:49', NULL),
(12672, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:00', NULL),
(12673, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:00', NULL),
(12674, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:26', NULL),
(12675, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:26', NULL),
(12676, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:29', NULL),
(12677, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:29', NULL),
(12678, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:31', NULL),
(12679, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:33', NULL),
(12680, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:36', NULL),
(12681, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:37', NULL),
(12682, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:37', NULL),
(12683, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:37', NULL),
(12684, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:43', NULL),
(12685, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dww.pdf (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:00:43', NULL),
(12686, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:43', NULL),
(12687, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:53', NULL),
(12688, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:00:53', NULL),
(12689, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:01:38', NULL),
(12690, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:01:43', NULL),
(12691, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dww.pdf (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:01:43', NULL),
(12692, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:01:43', NULL),
(12693, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:01:47', NULL),
(12694, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:01:49', NULL),
(12695, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:01:51', NULL),
(12696, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:01:54', NULL),
(12697, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:04:02', NULL),
(12698, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:04:04', NULL),
(12699, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:04:05', NULL),
(12700, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:04:20', NULL),
(12701, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:05:15', NULL),
(12702, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:05:28', NULL),
(12703, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dww.pdf (Doc #: 2, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:05:28', NULL),
(12704, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:05:28', NULL),
(12705, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:05:33', NULL),
(12706, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:05:35', NULL),
(12707, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:05:38', NULL),
(12708, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:06:16', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(12709, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawdawda.pdf (Doc #: 2, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:06:16', NULL),
(12710, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:06:16', NULL),
(12711, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:28:58', NULL),
(12712, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:40:39', NULL),
(12713, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:41:10', NULL),
(12714, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dasd das dasd.docx to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:41:10', NULL),
(12715, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:41:15', NULL),
(12716, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:41:20', NULL),
(12717, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:41:25', NULL),
(12718, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:41:29', NULL),
(12719, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:41:57', NULL),
(12720, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:42:35', NULL),
(12721, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:42:50', NULL),
(12722, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:42:54', NULL),
(12723, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawdw dwad daa.docx to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:42:55', NULL),
(12724, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: dawd dawd dadw.pdf to employee documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:42:55', NULL),
(12725, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:43:01', NULL),
(12726, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:43:08', NULL),
(12727, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:43:11', NULL),
(12728, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:43:16', NULL),
(12729, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:43:19', NULL),
(12730, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:43:19', NULL),
(12731, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:44:57', NULL),
(12732, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:47:46', NULL),
(12733, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:47:49', NULL),
(12734, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:48:00', NULL),
(12735, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:48:04', NULL),
(12736, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:48:37', NULL),
(12737, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:01', NULL),
(12738, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:13', NULL),
(12739, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:39', NULL),
(12740, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dwdw.docx (Doc #: 2, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 07:49:39', NULL),
(12741, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:39', NULL),
(12742, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:40', NULL),
(12743, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:48', NULL),
(12744, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:48', NULL),
(12745, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:49:59', NULL),
(12746, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:54:27', NULL),
(12747, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:55:00', NULL),
(12748, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:55:49', NULL),
(12749, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:55:52', NULL),
(12750, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:55:55', NULL),
(12751, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:55:59', NULL),
(12752, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:55:59', NULL),
(12753, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:56:11', NULL),
(12754, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:57:34', NULL),
(12755, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:57:34', NULL),
(12756, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:57:35', NULL),
(12757, 120, 'dawdaw, dadaw dawd', 'client', 'Page Access', 'Page Access', 'Accessed page: client_about', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:57:39', NULL),
(12758, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:57:59', NULL),
(12759, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:58:12', NULL),
(12760, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:59:35', NULL),
(12761, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 07:59:38', NULL),
(12762, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:01:14', NULL),
(12763, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:01:38', NULL),
(12764, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:02:46', NULL),
(12765, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:02:48', NULL),
(12766, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:07:01', NULL),
(12767, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:11:43', NULL),
(12768, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:11:47', NULL),
(12769, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:11:51', NULL),
(12770, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:11:52', NULL),
(12771, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:11:59', NULL),
(12772, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:12:01', NULL),
(12773, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:12:20', NULL),
(12774, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:15:31', NULL),
(12775, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:18:45', NULL),
(12776, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:18:57', NULL),
(12777, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:18:58', NULL),
(12778, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:19:59', NULL),
(12779, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:21:50', NULL),
(12780, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:24:11', NULL),
(12781, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:24:17', NULL),
(12782, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:24:19', NULL),
(12783, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:24:30', NULL),
(12784, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:26:43', NULL),
(12785, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:26:46', NULL),
(12786, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:27:09', NULL),
(12787, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:27:16', NULL),
(12788, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:27:19', NULL),
(12789, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:27:26', NULL),
(12790, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:27:50', NULL),
(12791, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:27:54', NULL),
(12792, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:28:08', NULL),
(12793, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:28:24', NULL),
(12794, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:28:24', NULL),
(12795, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:28:37', NULL),
(12796, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:28:46', NULL),
(12797, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:28:56', NULL),
(12798, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:29:00', NULL),
(12799, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:29:31', NULL),
(12800, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:29:36', NULL),
(12801, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:29:41', NULL),
(12802, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:29:47', NULL),
(12803, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:29:56', NULL),
(12804, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:29:59', NULL),
(12805, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:30:02', NULL),
(12806, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:30:14', NULL),
(12807, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:35:05', NULL),
(12808, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:21', NULL),
(12809, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:42', NULL),
(12810, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:45', NULL),
(12811, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:46', NULL),
(12812, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:46', NULL),
(12813, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:46', NULL),
(12814, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:52', NULL),
(12815, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:53', NULL),
(12816, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:36:53', NULL),
(12817, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 08:37:00', NULL),
(12818, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:32:53', NULL),
(12819, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:33:13', NULL),
(12820, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:36:05', NULL),
(12821, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:36:10', NULL),
(12822, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:38:25', NULL),
(12823, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:38:29', NULL),
(12824, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:39:16', NULL),
(12825, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:39:19', NULL),
(12826, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:39:33', NULL),
(12827, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:39:35', NULL),
(12828, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:41:57', NULL),
(12829, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:42:02', NULL),
(12830, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:42:59', NULL),
(12831, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:43:28', NULL),
(12832, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:43:45', NULL),
(12833, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:44:06', NULL),
(12834, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:45:33', NULL),
(12835, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:47:26', NULL),
(12836, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:47:28', NULL),
(12837, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:51:11', NULL),
(12838, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:51:16', NULL),
(12839, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:54:52', NULL),
(12840, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:55:01', NULL),
(12841, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:57:14', NULL),
(12842, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:57:44', NULL),
(12843, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: wda.docx (Doc #: 2, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 09:57:44', NULL),
(12844, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:57:44', NULL),
(12845, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:57:45', NULL),
(12846, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:57:58', NULL),
(12847, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:58:23', NULL),
(12848, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:58:31', NULL),
(12849, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:58:50', NULL),
(12850, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 09:58:57', NULL),
(12851, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:03:10', NULL),
(12852, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:05:51', NULL),
(12853, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:05:55', NULL),
(12854, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:09', NULL),
(12855, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:10', NULL),
(12856, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:16', NULL),
(12857, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:22', NULL),
(12858, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:30', NULL),
(12859, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dwawa.pdf (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:06:30', NULL),
(12860, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:30', NULL),
(12861, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:36', NULL),
(12862, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dwawa.pdf (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:06:36', NULL),
(12863, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:36', NULL),
(12864, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:42', NULL),
(12865, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: dwawadawdwa.pdf (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:06:42', NULL),
(12866, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:06:42', NULL),
(12867, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:07:07', NULL),
(12868, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:07:07', NULL),
(12869, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:07:11', NULL),
(12870, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:11:11', NULL),
(12871, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:11:15', NULL),
(12872, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:11:28', NULL),
(12873, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:11:28', NULL),
(12874, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dwadaw.pdf (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:11:28', NULL),
(12875, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:11:30', NULL),
(12876, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:11:34', NULL),
(12877, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:11:47', NULL),
(12878, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:11:48', NULL),
(12879, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: WEEK 9-10 Mendoza Miranda Refrea Sarino Soriano.pdf to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:11:48', NULL),
(12880, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:11:51', NULL),
(12881, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:12:15', NULL),
(12882, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:12:16', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(12883, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:12:32', NULL),
(12884, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:12:33', NULL),
(12885, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:23:36', NULL),
(12886, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:23:39', NULL),
(12887, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:23:44', NULL),
(12888, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:23:56', NULL),
(12889, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:23:56', NULL),
(12890, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.pdf (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:23:56', NULL),
(12891, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:24:03', NULL),
(12892, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:24:09', NULL),
(12893, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:25:44', NULL),
(12894, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:25:46', NULL),
(12895, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:25:50', NULL),
(12896, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:25:54', NULL),
(12897, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:26:00', NULL),
(12898, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:26:00', NULL),
(12899, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:26:14', NULL),
(12900, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:26:24', NULL),
(12901, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:26:24', NULL),
(12902, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:36:17', NULL),
(12903, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:36:25', NULL),
(12904, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:36:25', NULL),
(12905, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:36:36', NULL),
(12906, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:36:36', NULL),
(12907, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:36:40', NULL),
(12908, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:36:40', NULL),
(12909, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:37:55', NULL),
(12910, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:38:25', NULL),
(12911, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:38:39', NULL),
(12912, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:38:40', NULL),
(12913, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:45:34', NULL),
(12914, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:45:38', NULL),
(12915, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: wda.docx (Doc #: 2, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:45:38', NULL),
(12916, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:45:38', NULL),
(12917, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:45:39', NULL),
(12918, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:45:47', NULL),
(12919, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:45:47', NULL),
(12920, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:51:37', NULL),
(12921, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:51:42', NULL),
(12922, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:51:42', NULL),
(12923, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:52:02', NULL),
(12924, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:52:13', NULL),
(12925, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:52:18', NULL),
(12926, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:52:18', NULL),
(12927, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:54:24', NULL),
(12928, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:54:30', NULL),
(12929, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: wda.docx (Doc #: 2, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:54:30', NULL),
(12930, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:54:30', NULL),
(12931, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:54:32', NULL),
(12932, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:54:44', NULL),
(12933, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:54:44', NULL),
(12934, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:55:56', NULL),
(12935, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:55:56', NULL),
(12936, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:02', NULL),
(12937, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:08', NULL),
(12938, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: wda.docx (Doc #: 1, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:56:08', NULL),
(12939, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:08', NULL),
(12940, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:09', NULL),
(12941, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:16', NULL),
(12942, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:23', NULL),
(12943, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:34', NULL),
(12944, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawdawda.pdf (Doc #: 3, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:56:34', NULL),
(12945, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:34', NULL),
(12946, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:36', NULL),
(12947, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:56:44', NULL),
(12948, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:07', NULL),
(12949, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:08', NULL),
(12950, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:10', NULL),
(12951, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:13', NULL),
(12952, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:14', NULL),
(12953, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:20', NULL),
(12954, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:20', NULL),
(12955, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:21', NULL),
(12956, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:21', NULL),
(12957, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:26', NULL),
(12958, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:27', NULL),
(12959, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:28', NULL),
(12960, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:30', NULL),
(12961, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:57:39', NULL),
(12962, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:58:08', NULL),
(12963, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:58:17', NULL),
(12964, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.docx (Category: Law Office Files, Doc #: 0, Book #: 0)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:58:18', NULL),
(12965, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:58:20', NULL),
(12966, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:58:34', NULL),
(12967, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 10:58:42', NULL),
(12968, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 3.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 10:58:43', NULL),
(12969, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:02:48', NULL),
(12970, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:02:58', NULL),
(12971, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx (Category: Law Office Files, Doc #: 0, Book #: 0)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 11:02:59', NULL),
(12972, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:02', NULL),
(12973, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:08', NULL),
(12974, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawdawda.pdf (Category: Notarized Documents, Doc #: 4, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 11:03:08', NULL),
(12975, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:08', NULL),
(12976, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:16', NULL),
(12977, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:16', NULL),
(12978, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:20', NULL),
(12979, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:21', NULL),
(12980, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:26', NULL),
(12981, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:26', NULL),
(12982, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:31', NULL),
(12983, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dasd, das dasd.docx (Category: Notarized Documents, Doc #: 3, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 11:03:31', NULL),
(12984, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:31', NULL),
(12985, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:40', NULL),
(12986, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:40', NULL),
(12987, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:55', NULL),
(12988, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: wda.docx (Category: Notarized Documents, Doc #: 13, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-02 11:03:55', NULL),
(12989, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-02 11:03:55', NULL),
(12990, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:09:39', NULL),
(12991, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:09:40', NULL),
(12992, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:09:41', NULL),
(12993, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:10:36', NULL),
(12994, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:10:38', NULL),
(12995, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:11:27', NULL),
(12996, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:11:52', NULL),
(12997, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dwadaw.pdf (Category: Notarized Documents, Doc #: 4, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:11:52', NULL),
(12998, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:11:52', NULL),
(12999, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:11:57', NULL),
(13000, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dwadaw.pdf (Category: Notarized Documents, Doc #: 4, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:11:57', NULL),
(13001, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:11:57', NULL),
(13002, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:12:29', NULL),
(13003, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:12:35', NULL),
(13004, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawd dawd daw.docx (Category: Notarized Documents, Doc #: 12, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:12:36', NULL),
(13005, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw awdaw dawdaw.pdf (Category: Notarized Documents, Doc #: 17, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:12:36', NULL),
(13006, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:12:37', NULL),
(13007, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:12:47', NULL),
(13008, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dwadaw.pdf (Category: Notarized Documents, Doc #: 4, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:12:47', NULL),
(13009, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:12:47', NULL),
(13010, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:12:53', NULL),
(13011, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dwadaw.pdf (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:12:53', NULL),
(13012, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:12:53', NULL),
(13013, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:02', NULL),
(13014, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dasd, das dasd.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:13:02', NULL),
(13015, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:02', NULL),
(13016, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:22', NULL),
(13017, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:22', NULL),
(13018, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:37', NULL),
(13019, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:50', NULL),
(13020, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:13:50', NULL),
(13021, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.pdf (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:13:50', NULL),
(13022, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:55', NULL),
(13023, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:56', NULL),
(13024, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:56', NULL),
(13025, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:57', NULL),
(13026, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:57', NULL),
(13027, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:13:57', NULL),
(13028, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:08', NULL),
(13029, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:14:09', NULL),
(13030, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.pdf (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:14:09', NULL),
(13031, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:12', NULL),
(13032, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:13', NULL),
(13033, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:20', NULL),
(13034, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: daw.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:14:21', NULL),
(13035, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:25', NULL),
(13036, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:31', NULL),
(13037, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: daw.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:14:31', NULL),
(13038, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:31', NULL),
(13039, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:35', NULL),
(13040, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: dawdawd.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:14:35', NULL),
(13041, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:14:35', NULL),
(13042, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:17:48', NULL),
(13043, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:17:51', NULL),
(13044, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:17:56', NULL),
(13045, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:17:58', NULL),
(13046, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:17:59', NULL),
(13047, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:18:02', NULL),
(13048, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:18:08', NULL),
(13049, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:18:17', NULL),
(13050, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:20:49', NULL),
(13051, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:22', NULL),
(13052, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:23', NULL),
(13053, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:23', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(13054, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:34', NULL),
(13055, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:40', NULL),
(13056, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:44', NULL),
(13057, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:44', NULL),
(13058, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:22:45', NULL),
(13059, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:23:02', NULL),
(13060, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:23:04', NULL),
(13061, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:23:08', NULL),
(13062, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:26:26', NULL),
(13063, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:26:32', NULL),
(13064, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:26:54', NULL),
(13065, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:28:21', NULL),
(13066, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:28:24', NULL),
(13067, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:28:27', NULL),
(13068, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:28:36', NULL),
(13069, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:29:03', NULL),
(13070, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:29:03', NULL),
(13071, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:29:06', NULL),
(13072, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:29:11', NULL),
(13073, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:30:55', NULL),
(13074, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:30:55', NULL),
(13075, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:30:56', NULL),
(13076, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:01', NULL),
(13077, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:04', NULL),
(13078, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:08', NULL),
(13079, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:08', NULL),
(13080, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:11', NULL),
(13081, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:12', NULL),
(13082, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_cases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:13', NULL),
(13083, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:25', NULL),
(13084, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:31:44', NULL),
(13085, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:33:40', NULL),
(13086, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:33:43', NULL),
(13087, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:33:45', NULL),
(13088, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:33:47', NULL),
(13089, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:34:01', NULL),
(13090, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:35:02', NULL),
(13091, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:38:35', NULL),
(13092, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:38:36', NULL),
(13093, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:38:45', NULL),
(13094, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:38:47', NULL),
(13095, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:38:49', NULL),
(13096, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:05', NULL),
(13097, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:06', NULL),
(13098, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:12', NULL),
(13099, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:43', NULL),
(13100, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:45', NULL),
(13101, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:47', NULL),
(13102, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:56', NULL),
(13103, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:39:57', NULL),
(13104, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:40:00', NULL),
(13105, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:40:12', NULL),
(13106, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:40:12', NULL),
(13107, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:40:13', NULL),
(13108, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:40:22', NULL),
(13109, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:41:47', NULL),
(13110, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:41:49', NULL),
(13111, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:41:50', NULL),
(13112, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:41:52', NULL),
(13113, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:41:56', NULL),
(13114, 119, 'dawd, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: dawdaw.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:41:56', NULL),
(13115, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:41:56', NULL),
(13116, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:42:00', NULL),
(13117, 119, 'dawd, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: dwadaw.pdf (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:42:00', NULL),
(13118, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:42:00', NULL),
(13119, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:42:05', NULL),
(13120, 119, 'dawd, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: dawdaw.pdf (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:42:05', NULL),
(13121, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:42:05', NULL),
(13122, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:42:09', NULL),
(13123, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:42:53', NULL),
(13124, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:43:07', NULL),
(13125, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:46:29', NULL),
(13126, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:46:53', NULL),
(13127, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:47:06', NULL),
(13128, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:47:08', NULL),
(13129, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:47:16', NULL),
(13130, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:49:25', NULL),
(13131, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:49:34', NULL),
(13132, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:49:51', NULL),
(13133, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:49:58', NULL),
(13134, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:07', NULL),
(13135, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: w.docx (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:50:07', NULL),
(13136, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:07', NULL),
(13137, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:12', NULL),
(13138, 119, 'dawd, dawd dawd', 'attorney', 'Document Edit', 'Document Management', 'Edited document: ww.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:50:12', NULL),
(13139, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:12', NULL),
(13140, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:17', NULL),
(13141, 119, 'dawd, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: ww.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:50:17', NULL),
(13142, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:17', NULL),
(13143, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:23', NULL),
(13144, 119, 'dawd, dawd dawd', 'attorney', 'Document Delete', 'Document Management', 'Deleted document: dawdwa.docx (Category: Court Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:50:23', NULL),
(13145, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:23', NULL),
(13146, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:39', NULL),
(13147, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:41', NULL),
(13148, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:50:43', NULL),
(13149, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:22', NULL),
(13150, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:26', NULL),
(13151, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:28', NULL),
(13152, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:32', NULL),
(13153, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:35', NULL),
(13154, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:37', NULL),
(13155, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:40', NULL),
(13156, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:42', NULL),
(13157, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:45', NULL),
(13158, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:48', NULL),
(13159, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:51', NULL),
(13160, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:52', NULL),
(13161, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:54:55', NULL),
(13162, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:03', NULL),
(13163, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:10', NULL),
(13164, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:12', NULL),
(13165, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:16', NULL),
(13166, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Delete', 'Document Management', 'Deleted document: dawdaw, awdaw dawdaw (Category: Notarized Documents, Doc #: 17, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:55:16', NULL),
(13167, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:16', NULL),
(13168, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:33', NULL),
(13169, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:36', NULL),
(13170, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Delete', 'Document Management', 'Deleted document: dawdaw (Category: Law Office Files, Doc #: 0, Book #: 0)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:55:36', NULL),
(13171, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:36', NULL),
(13172, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:48', NULL),
(13173, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:55:48', NULL),
(13174, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:14', NULL),
(13175, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:14', NULL),
(13176, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:29', NULL),
(13177, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: w.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:56:29', NULL),
(13178, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:29', NULL),
(13179, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:34', NULL),
(13180, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:34', NULL),
(13181, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:42', NULL),
(13182, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:45', NULL),
(13183, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:46', NULL),
(13184, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:48', NULL),
(13185, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Delete', 'Document Management', 'Deleted document: dawdw, dwad daa (Category: Notarized Documents, Doc #: 4, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:56:48', NULL),
(13186, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:48', NULL),
(13187, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:56', NULL),
(13188, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:56:56', NULL),
(13189, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:05', NULL),
(13190, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:07', NULL),
(13191, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:30', NULL),
(13192, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:30', NULL),
(13193, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:39', NULL),
(13194, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Delete', 'Document Management', 'Deleted document: dawd, dawd dadw (Category: Notarized Documents, Doc #: 4, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:57:39', NULL),
(13195, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:39', NULL),
(13196, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:42', NULL),
(13197, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:44', NULL),
(13198, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Delete', 'Document Management', 'Deleted document: w.docx (Category: Notarized Documents, Doc #: 2, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 02:57:44', NULL),
(13199, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:44', NULL),
(13200, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:44', NULL),
(13201, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:47', NULL),
(13202, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:49', NULL),
(13203, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:51', NULL),
(13204, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:53', NULL),
(13205, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:55', NULL),
(13206, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:59', NULL),
(13207, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dawd, dawd daw.docx (Category: Notarized Documents, Doc #: 12, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:57:59', NULL),
(13208, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:57:59', NULL),
(13209, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:03', NULL),
(13210, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:05', NULL),
(13211, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:08', NULL),
(13212, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:11', NULL),
(13213, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:18', NULL),
(13214, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dwadaw.pdf (Category: Notarized Documents, Doc #: 11, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:58:18', NULL),
(13215, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:18', NULL),
(13216, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:25', NULL),
(13217, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:31', NULL),
(13218, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Edit', 'Document Management', 'Edited document: dwadaw.pdf (Category: Notarized Documents, Doc #: 4, Book #: 11)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 02:58:31', NULL),
(13219, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:32', NULL),
(13220, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:35', NULL),
(13221, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:36', NULL),
(13222, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 02:58:37', NULL),
(13223, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:01:05', NULL),
(13224, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:01:07', NULL),
(13225, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:01:09', NULL),
(13226, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:01:16', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(13227, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:02:44', NULL),
(13228, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:02:57', NULL),
(13229, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:14', NULL),
(13230, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:16', NULL),
(13231, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:18', NULL),
(13232, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:20', NULL),
(13233, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:25', NULL),
(13234, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dawdawd.docx (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 03:03:25', NULL),
(13235, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:25', NULL),
(13236, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:31', NULL),
(13237, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dwawadawdwa.pdf (Source: attorney)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 03:03:31', NULL),
(13238, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:31', NULL),
(13239, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:39', NULL),
(13240, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: w.docx (Category: Client Documents)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:03:39', NULL),
(13241, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:39', NULL),
(13242, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:48', NULL),
(13243, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited attorney document: w.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:03:48', NULL),
(13244, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:03:48', NULL),
(13245, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:05', NULL),
(13246, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:12', NULL),
(13247, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: dwadaw.pdf (Doc #: 4, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 03:04:12', NULL),
(13248, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:12', NULL),
(13249, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:17', NULL),
(13250, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Edit', 'Document Management', 'Edited document: dawd, dawd daw.docx (Doc #: 11, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:04:17', NULL),
(13251, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:17', NULL),
(13252, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:18', NULL),
(13253, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:24', NULL),
(13254, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Delete', 'Document Management', 'Deleted document: wda.docx (Doc #: 13, Book #: 11, Source: employee)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'high', '2025-11-03 03:04:24', NULL),
(13255, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:24', NULL),
(13256, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:45', NULL),
(13257, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:52', NULL),
(13258, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:53', NULL),
(13259, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:55', NULL),
(13260, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:56', NULL),
(13261, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:56', NULL),
(13262, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:58', NULL),
(13263, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:04:59', NULL),
(13264, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:00', NULL),
(13265, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_document_generation', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:36', NULL),
(13266, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_usermanagement', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:37', NULL),
(13267, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:39', NULL),
(13268, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:40', NULL),
(13269, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:42', NULL),
(13270, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:43', NULL),
(13271, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:44', NULL),
(13272, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:05:45', NULL),
(13273, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:06:00', NULL),
(13274, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:06:07', NULL),
(13275, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:06:08', NULL),
(13276, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:06:13', NULL),
(13277, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:06:21', NULL),
(13278, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Document Upload', 'Document Management', 'Uploaded document: 1761728229_0_dawdaw 2.docx to attorney documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:06:21', NULL),
(13279, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:09:31', NULL),
(13280, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:11:27', NULL),
(13281, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:11:33', NULL),
(13282, 119, 'dawd, dawd dawd', 'attorney', 'Document Upload', 'Document Management', 'Uploaded document: dawdwa.docx (Category: Case Files)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:11:34', NULL),
(13283, 119, 'dawd, dawd dawd', 'attorney', 'Page Access', 'Page Access', 'Accessed page: attorney_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:11:36', NULL),
(13284, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:11:45', NULL),
(13285, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:11:57', NULL),
(13286, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Document Upload', 'Document Management', 'Uploaded document: dawdaw.docx (Category: Law Office Files, Doc #: 0, Book #: 0)', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:11:57', NULL),
(13287, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:11:59', NULL),
(13288, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:26:27', NULL),
(13289, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_managecases', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:26:46', NULL),
(13290, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:26:51', NULL),
(13291, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:26:52', NULL),
(13292, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_audit', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:26:52', NULL),
(13293, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:26:54', NULL),
(13294, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:31:30', NULL),
(13295, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:34:32', NULL),
(13296, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:35:53', NULL),
(13297, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:35:54', NULL),
(13298, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:35:55', NULL),
(13299, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:36:00', NULL),
(13300, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:37:09', NULL),
(13301, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:37:11', NULL),
(13302, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:37:13', NULL),
(13303, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:37:21', NULL),
(13304, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:40:14', NULL),
(13305, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:40:34', NULL),
(13306, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dawd, dwad dad (Contact: 12312312312); Type: Free Legal Advice; Date: 2025-11-04; Time: 12:42-13:12; Location: dawd', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:42:20', NULL),
(13307, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:42:38', NULL),
(13308, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Event Status Update', 'Case Management', 'Updated event #87 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 03:42:47', NULL),
(13309, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:43:00', NULL),
(13310, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:43:58', NULL),
(13311, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:44:12', NULL),
(13312, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: adsda, asdasd asdasd (Contact: 12312312312); Type: Appointment; Date: 2025-11-05; Time: 12:43-13:13; Location: asdasd', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:44:34', NULL),
(13313, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dasdadwdawd, dwadaw (Contact: 12312312312); Type: Appointment; Date: 2025-11-07; Time: 12:48-13:18; Location: dawdaw', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:48:19', NULL),
(13314, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:48:25', NULL),
(13315, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:48:46', NULL),
(13316, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:49:29', NULL),
(13317, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:49:50', NULL),
(13318, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:57:46', NULL),
(13319, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dawd, dawd daw (Contact: 12312312312); Type: Free Legal Advice; Date: 2025-11-04; Time: 12:58-13:28; Location: dawdwa', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 03:58:12', NULL),
(13320, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:58:18', NULL),
(13321, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Event Status Update', 'Case Management', 'Updated event #90 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 03:58:26', NULL),
(13322, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 03:59:30', NULL),
(13323, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:00:31', NULL),
(13324, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:04:06', NULL),
(13325, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:04:08', NULL),
(13326, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:04:21', NULL),
(13327, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:06:14', NULL),
(13328, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:10:53', NULL),
(13329, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:11:46', NULL),
(13330, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:12:04', NULL),
(13331, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:12:18', NULL),
(13332, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:12:23', NULL),
(13333, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:12:36', NULL),
(13334, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:12:45', NULL),
(13335, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:13:12', NULL),
(13336, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:14:03', NULL),
(13337, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:15:05', NULL),
(13338, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:15:13', NULL),
(13339, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:15:19', NULL),
(13340, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:15:34', NULL),
(13341, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:15:44', NULL),
(13342, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:16:29', NULL),
(13343, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:21:33', NULL),
(13344, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dawd, dwad dwadw (Contact: 12312312312); Type: Free Legal Advice; Date: 2025-11-04; Time: 16:25-16:55; Location: dawdadwa', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 04:25:33', NULL),
(13345, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:25:38', NULL),
(13346, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:26:12', NULL),
(13347, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Event Status Update', 'Case Management', 'Updated event #91 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 04:27:10', NULL),
(13348, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:30:16', NULL),
(13349, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:31:20', NULL),
(13350, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:31:24', NULL),
(13351, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:31:26', NULL),
(13352, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:33:17', NULL),
(13353, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:38:39', NULL),
(13354, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dsadds, dada 12 (Contact: 12312312312); Type: Appointment; Date: 2025-11-04; Time: 15:38-16:08; Location: dwad', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 04:39:06', NULL),
(13355, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:39:13', NULL),
(13356, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Event Status Update', 'Case Management', 'Updated event #92 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 04:39:55', NULL),
(13357, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:40:29', NULL),
(13358, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 04:51:18', NULL),
(13359, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:00:15', NULL),
(13360, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:01:49', NULL),
(13361, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:02:06', NULL),
(13362, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:02:14', NULL),
(13363, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:03:24', NULL),
(13364, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:05:10', NULL),
(13365, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:05:30', NULL),
(13366, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:06:02', NULL),
(13367, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dsada, dadas (Contact: 12312312312); Type: Appointment; Date: 2025-11-05; Time: 13:06-13:36; Location: dwadwa', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 05:06:44', NULL),
(13368, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:06:48', NULL),
(13369, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Event Status Update', 'Case Management', 'Updated event #93 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 05:07:53', NULL),
(13370, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:12:09', NULL),
(13371, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:12:23', NULL),
(13372, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:12:54', NULL),
(13373, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:14:06', NULL),
(13374, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:18:31', NULL),
(13375, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:19:11', NULL),
(13376, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:21:42', NULL),
(13377, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:23:56', NULL),
(13378, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:25:58', NULL),
(13379, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:28:56', NULL),
(13380, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:55:33', NULL),
(13381, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:57:52', NULL),
(13382, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:57:59', NULL),
(13383, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 05:58:08', NULL),
(13384, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dawdaw, dadw (Contact: 12312312312); Type: Free Legal Advice; Date: 2025-11-04; Time: 14:59-15:29; Location: dawdwa', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 05:59:39', NULL),
(13385, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Event Status Update', 'Case Management', 'Updated event #94 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 06:02:49', NULL),
(13386, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:12:18', NULL),
(13387, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:12:19', NULL),
(13388, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:12:24', NULL),
(13389, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:12:26', NULL),
(13390, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:12:42', NULL),
(13391, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:13:22', NULL),
(13392, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:16:03', NULL),
(13393, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:16:16', NULL),
(13394, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dawdwa, dawdwa (Contact: 12312312312); Type: Appointment; Date: 2025-11-05; Time: 15:16-15:46; Location: dawdaw', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 06:16:34', NULL);
INSERT INTO `audit_trail` (`id`, `user_id`, `user_name`, `user_type`, `action`, `module`, `description`, `ip_address`, `user_agent`, `status`, `priority`, `timestamp`, `additional_data`) VALUES
(13395, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:16:40', NULL),
(13396, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:18:04', NULL),
(13397, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Event Status Update', 'Case Management', 'Updated event #95 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 06:18:08', NULL),
(13398, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:18:46', NULL),
(13399, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Walk-in Schedule Created', 'Schedule Management', 'Created by: Nerfy, Yuhan Santiago; Attorney: Opiña, Leif Laiglon Abriz; Walk-in Client: dasd, dawda (Contact: 12312312312); Type: Free Legal Advice; Date: 2025-11-04; Time: 14:19-14:49; Location: dawdaw', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'medium', '2025-11-03 06:19:13', NULL),
(13400, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:19:19', NULL),
(13401, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Event Status Update', 'Case Management', 'Updated event #96 status to: Completed', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'warning', 'medium', '2025-11-03 06:19:27', NULL),
(13402, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:20:46', NULL),
(13403, 1, 'Opiña, Leif Laiglon Abriz', 'admin', 'Page Access', 'Page Access', 'Accessed page: admin_schedule', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:20:56', NULL),
(13404, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_request_management', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:39:58', NULL),
(13405, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_clients', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:39:59', NULL),
(13406, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_messages', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:40:00', NULL),
(13407, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:40:05', NULL),
(13408, 118, 'Nerfy, Yuhan Santiago', 'employee', 'Page Access', 'Page Access', 'Accessed page: employee_documents', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'success', 'low', '2025-11-03 06:40:13', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `available_colors`
--

CREATE TABLE `available_colors` (
  `id` int(11) NOT NULL,
  `schedule_card_color` varchar(7) NOT NULL,
  `calendar_event_color` varchar(7) NOT NULL,
  `color_name` varchar(50) NOT NULL,
  `is_available` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `case_documents`
--

CREATE TABLE `case_documents` (
  `id` int(11) NOT NULL,
  `case_id` int(11) NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_path` varchar(500) NOT NULL,
  `category` varchar(100) NOT NULL,
  `uploaded_by` int(11) NOT NULL,
  `file_size` int(11) NOT NULL,
  `file_type` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `uploaded_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `case_schedules`
--

CREATE TABLE `case_schedules` (
  `id` int(11) NOT NULL,
  `case_id` int(11) DEFAULT NULL,
  `attorney_id` int(11) DEFAULT NULL,
  `client_id` int(11) DEFAULT NULL,
  `walkin_client_name` varchar(255) DEFAULT NULL,
  `walkin_client_contact` varchar(50) DEFAULT NULL,
  `type` enum('Hearing','Appointment','Free Legal Advice') NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `date` date NOT NULL,
  `start_time` time NOT NULL,
  `end_time` time NOT NULL,
  `location` varchar(255) DEFAULT NULL,
  `created_by_employee_id` int(11) DEFAULT NULL,
  `status` varchar(50) DEFAULT 'Scheduled',
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `case_schedules`
--

INSERT INTO `case_schedules` (`id`, `case_id`, `attorney_id`, `client_id`, `walkin_client_name`, `walkin_client_contact`, `type`, `title`, `description`, `date`, `start_time`, `end_time`, `location`, `created_by_employee_id`, `status`, `created_at`) VALUES
(94, NULL, 1, NULL, 'dawdaw, dadw', '12312312312', 'Free Legal Advice', '', 'dawdwadawdwa', '2025-11-04', '14:59:00', '15:29:00', 'dawdwa', 118, 'Completed', '2025-11-03 13:59:39'),
(96, NULL, 1, NULL, 'dasd, dawda', '12312312312', 'Free Legal Advice', '', 'dawdawdaw', '2025-11-04', '14:19:00', '14:49:00', 'dawdaw', 118, 'Completed', '2025-11-03 14:19:13');

-- --------------------------------------------------------

--
-- Table structure for table `client_attorney_assignments`
--

CREATE TABLE `client_attorney_assignments` (
  `id` int(11) NOT NULL,
  `conversation_id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `attorney_id` int(11) NOT NULL,
  `assigned_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `seen_status` enum('Not Seen','Seen') DEFAULT 'Not Seen'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_attorney_conversations`
--

CREATE TABLE `client_attorney_conversations` (
  `id` int(11) NOT NULL,
  `assignment_id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `attorney_id` int(11) NOT NULL,
  `conversation_status` enum('Active','Completed','Closed') DEFAULT 'Active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_attorney_messages`
--

CREATE TABLE `client_attorney_messages` (
  `id` int(11) NOT NULL,
  `conversation_id` int(11) NOT NULL,
  `sender_id` int(11) NOT NULL,
  `sender_type` enum('client','attorney') NOT NULL,
  `message` text NOT NULL,
  `is_read` tinyint(1) DEFAULT 0,
  `sent_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `is_seen` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_document_generation`
--

CREATE TABLE `client_document_generation` (
  `id` int(11) NOT NULL,
  `request_id` varchar(100) NOT NULL,
  `client_id` int(11) NOT NULL,
  `document_type` varchar(100) NOT NULL,
  `document_data` text NOT NULL,
  `pdf_file_path` varchar(500) DEFAULT NULL,
  `pdf_filename` varchar(255) DEFAULT NULL,
  `status` enum('Pending','Approved','Rejected') DEFAULT 'Pending',
  `rejection_reason` text DEFAULT NULL,
  `submitted_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `reviewed_at` timestamp NULL DEFAULT NULL,
  `reviewed_by` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_employee_conversations`
--

CREATE TABLE `client_employee_conversations` (
  `id` int(11) NOT NULL,
  `request_form_id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `conversation_status` enum('Active','Completed','Closed') DEFAULT 'Active',
  `concern_identified` tinyint(1) DEFAULT 0,
  `concern_description` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_employee_messages`
--

CREATE TABLE `client_employee_messages` (
  `id` int(11) NOT NULL,
  `conversation_id` int(11) NOT NULL,
  `sender_id` int(11) NOT NULL,
  `sender_type` enum('client','employee') NOT NULL,
  `message` text NOT NULL,
  `is_read` tinyint(1) DEFAULT 0,
  `sent_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `is_seen` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_messages`
--

CREATE TABLE `client_messages` (
  `id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `recipient_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `sent_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `client_request_form`
--

CREATE TABLE `client_request_form` (
  `id` int(11) NOT NULL,
  `request_id` varchar(50) NOT NULL,
  `client_id` int(11) NOT NULL,
  `full_name` varchar(255) NOT NULL,
  `address` text NOT NULL,
  `sex` enum('Male','Female') NOT NULL,
  `valid_id_path` varchar(500) NOT NULL,
  `valid_id_filename` varchar(255) NOT NULL,
  `valid_id_front_path` varchar(500) NOT NULL,
  `valid_id_front_filename` varchar(255) NOT NULL,
  `valid_id_back_path` varchar(500) NOT NULL,
  `valid_id_back_filename` varchar(255) NOT NULL,
  `privacy_consent` tinyint(1) NOT NULL DEFAULT 0,
  `concern_description` text DEFAULT NULL,
  `legal_category` varchar(100) DEFAULT NULL,
  `urgency_level` enum('Low','Medium','High','Critical') DEFAULT 'Medium',
  `status` enum('Pending','Approved','Rejected') DEFAULT 'Pending',
  `submitted_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `reviewed_at` timestamp NULL DEFAULT NULL,
  `reviewed_by` int(11) DEFAULT NULL,
  `review_notes` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `document_requests`
--

CREATE TABLE `document_requests` (
  `id` int(11) NOT NULL,
  `case_id` int(11) NOT NULL,
  `attorney_id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `due_date` date DEFAULT NULL,
  `status` enum('Requested','Submitted','Reviewed','Approved','Rejected','Cancelled') DEFAULT 'Requested',
  `attorney_comment` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `document_request_comments`
--

CREATE TABLE `document_request_comments` (
  `id` int(11) NOT NULL,
  `request_id` int(11) NOT NULL,
  `attorney_id` int(11) NOT NULL,
  `comment` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `document_request_files`
--

CREATE TABLE `document_request_files` (
  `id` int(11) NOT NULL,
  `request_id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `file_path` varchar(500) NOT NULL,
  `original_name` varchar(255) NOT NULL,
  `uploaded_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `efiling_history`
--

CREATE TABLE `efiling_history` (
  `id` int(11) NOT NULL,
  `attorney_id` int(11) NOT NULL,
  `case_id` int(11) DEFAULT NULL,
  `document_category` varchar(50) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `original_file_name` varchar(255) DEFAULT NULL,
  `stored_file_path` varchar(500) DEFAULT NULL,
  `receiver_email` varchar(255) NOT NULL,
  `message` text DEFAULT NULL,
  `status` enum('Sent','Failed') NOT NULL DEFAULT 'Sent',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employee_documents`
--

CREATE TABLE `employee_documents` (
  `id` int(11) NOT NULL,
  `doc_number` int(11) NOT NULL,
  `book_number` int(11) NOT NULL,
  `document_name` varchar(255) DEFAULT NULL,
  `affidavit_type` varchar(100) DEFAULT NULL,
  `series` varchar(50) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `file_size` bigint(20) DEFAULT NULL,
  `file_type` varchar(50) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_path` varchar(255) NOT NULL,
  `category` varchar(100) NOT NULL,
  `uploaded_by` int(11) NOT NULL,
  `upload_date` datetime NOT NULL DEFAULT current_timestamp(),
  `is_deleted` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employee_document_activity`
--

CREATE TABLE `employee_document_activity` (
  `id` int(11) NOT NULL,
  `document_id` int(11) NOT NULL,
  `action` varchar(50) NOT NULL,
  `user_id` int(11) NOT NULL,
  `form_number` int(11) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `user_name` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employee_messages`
--

CREATE TABLE `employee_messages` (
  `id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `recipient_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `sent_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `is_read` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employee_request_reviews`
--

CREATE TABLE `employee_request_reviews` (
  `id` int(11) NOT NULL,
  `request_form_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `action` enum('Approved','Rejected') NOT NULL,
  `review_notes` text DEFAULT NULL,
  `reviewed_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `maintenance_settings`
--

CREATE TABLE `maintenance_settings` (
  `id` int(11) NOT NULL,
  `maintenance_mode` tinyint(1) DEFAULT 0,
  `maintenance_message` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `user_type` enum('admin','attorney','client','employee') NOT NULL,
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `type` enum('info','success','warning','error') DEFAULT 'info',
  `is_read` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `notifications`
--

INSERT INTO `notifications` (`id`, `user_id`, `user_type`, `title`, `message`, `type`, `is_read`, `created_at`) VALUES
(485, 101, 'client', 'Message Seen', 'Your attorney has seen your conversation.', 'info', 1, '2025-10-28 03:53:34'),
(486, 101, 'client', 'New Message Received', 'You received a new message from attorney: Atty. Soriano, France Opina - asdasd', 'info', 1, '2025-10-28 03:53:37'),
(487, 98, 'attorney', 'New Message Received', 'You received a new message from client: juan, cruz I - sdds', 'info', 1, '2025-10-28 03:54:25'),
(488, 101, 'client', 'Document Approved', 'Your PWD ID Loss document (Request ID: DOC_20251028045446_0101_3247) has been approved by our legal team. You can now proceed with the next steps.', 'success', 1, '2025-10-28 03:55:41'),
(489, 101, 'client', 'New Message Received', 'You received a new message from attorney: Atty. Soriano, France Opina - asdas', 'info', 1, '2025-10-28 04:23:33'),
(490, 101, 'client', 'New Schedule Created', 'A new Appointment has been scheduled for you on 2025-10-30 from 09:34 to 10:04 at Cabuyao', 'info', 1, '2025-10-28 04:31:47'),
(491, 94, 'employee', 'New Client Request', 'Client juan, cruz II has submitted a new messaging request (ID: REQ-20251028-0106-1248). Please review and process the request.', 'info', 0, '2025-10-28 06:06:19'),
(492, 105, 'employee', 'New Client Request', 'Client juan, cruz II has submitted a new messaging request (ID: REQ-20251028-0106-1248). Please review and process the request.', 'info', 0, '2025-10-28 06:06:19'),
(493, 106, 'client', 'Request Approved!', 'Your request has been approved! You can now start messaging with our team and your assigned attorney.', 'success', 0, '2025-10-28 06:06:44'),
(494, 98, 'attorney', 'New Client Assignment', 'You have been assigned to a new client: juan, cruz II. You can now start communicating with them.', 'success', 0, '2025-10-28 06:06:44'),
(495, 94, 'employee', 'New Client Request', 'Client Miranda, Kian Ligsay has submitted a new messaging request (ID: REQ-20251028-0107-3982). Please review and process the request.', 'info', 0, '2025-10-28 06:10:09'),
(496, 105, 'employee', 'New Client Request', 'Client Miranda, Kian Ligsay has submitted a new messaging request (ID: REQ-20251028-0107-3982). Please review and process the request.', 'info', 0, '2025-10-28 06:10:09'),
(497, 107, 'client', 'Request Approved!', 'Your request has been approved! You can now start messaging with our team and your assigned attorney.', 'success', 0, '2025-10-28 06:10:47'),
(498, 1, 'attorney', 'New Client Assignment', 'You have been assigned to a new client: Miranda, Kian Ligsay. You can now start communicating with them.', 'success', 1, '2025-10-28 06:10:47'),
(499, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - bastos', 'info', 0, '2025-10-28 06:38:53'),
(500, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - kk', 'info', 0, '2025-10-28 06:40:24'),
(501, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 06:42:51'),
(502, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 06:43:04'),
(503, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 06:46:09'),
(504, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - sad', 'info', 0, '2025-10-28 06:46:22'),
(505, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - Soriano vs Miranda', 'info', 0, '2025-10-28 06:49:44'),
(506, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 07:03:23'),
(507, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 07:05:14'),
(508, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 07:06:12'),
(509, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 07:06:30'),
(510, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 07:07:05'),
(511, 107, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - asd', 'info', 0, '2025-10-28 07:09:31'),
(512, 98, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-10-30 from 09:34:00 to 10:04:00 at Cabuyao', 'info', 0, '2025-10-29 10:32:05'),
(513, 101, 'client', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-10-30 from 09:34:00 to 10:04:00 at Cabuyao', 'info', 0, '2025-10-29 10:32:05'),
(514, 109, 'employee', 'New Client Request', 'Client dawd, dawd dadw has submitted a new messaging request (ID: REQ-20251029-0113-9889). Please review and process the request.', 'info', 0, '2025-10-29 12:17:33'),
(515, 111, 'employee', 'New Client Request', 'Client dawd, dawd dadw has submitted a new messaging request (ID: REQ-20251029-0113-9889). Please review and process the request.', 'info', 0, '2025-10-29 12:17:33'),
(516, 114, 'employee', 'New Client Request', 'Client dawd, dawd dadw has submitted a new messaging request (ID: REQ-20251029-0113-9889). Please review and process the request.', 'info', 0, '2025-10-29 12:17:33'),
(517, 113, 'client', 'Request Approved!', 'Your request has been approved! You can now start messaging with our team and your assigned attorney.', 'success', 0, '2025-10-29 12:23:03'),
(518, 1, 'attorney', 'New Client Assignment', 'You have been assigned to a new client: dawd, dawd dadw. You can now start communicating with them.', 'success', 1, '2025-10-29 12:23:03'),
(519, 117, 'employee', 'New Client Request', 'Client Refrea, Mar John Santiago has submitted a new messaging request (ID: REQ-20251029-0115-4876). Please review and process the request.', 'info', 0, '2025-10-29 14:32:48'),
(520, 107, 'client', 'Case Status Updated', 'Your case \'asd\' status has been updated to: Active', 'info', 0, '2025-10-29 14:36:01'),
(521, 115, 'client', 'Request Approved!', 'Your request has been approved! You can now start messaging with our team and your assigned attorney.', 'success', 0, '2025-10-29 14:40:08'),
(522, 116, 'attorney', 'New Client Assignment', 'You have been assigned to a new client: Refrea, Mar John Santiago. You can now start communicating with them.', 'success', 0, '2025-10-29 14:40:08'),
(523, 115, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: dawdw, dawd dawd - dawdawdwa', 'info', 0, '2025-10-29 14:56:00'),
(524, 115, 'client', 'New Schedule Created', 'A new Hearing has been scheduled for you on 2025-10-30 from 12:05 to 12:35 at dawdawd', 'info', 0, '2025-10-29 15:05:42'),
(525, 116, 'attorney', 'New Schedule Assigned', 'A new Free Legal Advice has been scheduled for you by employee: dawdw, dwad dawd on 2025-10-30 from 13:09 to 13:39 at dawdaw', 'info', 0, '2025-10-29 15:09:31'),
(526, 115, 'client', 'New Schedule Created', 'A new Free Legal Advice has been scheduled for you by employee: dawdw, dwad dawd on 2025-10-30 from 13:09 to 13:39 at dawdaw', 'info', 0, '2025-10-29 15:09:31'),
(527, 116, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by dawdw, dawd dawd on 2025-10-30 from 13:09:00 to 13:39:00 at dawdaw', 'info', 0, '2025-10-29 15:13:39'),
(528, 115, 'client', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by dawdw, dawd dawd on 2025-10-30 from 13:09:00 to 13:39:00 at dawdaw', 'info', 0, '2025-10-29 15:13:39'),
(529, 1, 'attorney', 'New Schedule Assigned', 'A new Appointment has been scheduled for you by employee: dawdw, dwad dawd on 2025-10-31 from 12:17 to 14:47 at dawdaw', 'info', 1, '2025-10-29 15:17:37'),
(530, 115, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - dawdwa', 'info', 0, '2025-10-30 08:42:08'),
(531, 115, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: dawdw, dawd dawd - dawdaw', 'info', 0, '2025-10-30 08:42:55'),
(532, 115, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - dawdaw', 'info', 0, '2025-10-30 08:47:20'),
(533, 115, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - dawdwa', 'info', 0, '2025-10-30 08:50:34'),
(534, 115, 'client', 'New Case Assigned', 'A new case has been created for you by attorney: Opiña, Leif Laiglon Abriz - dawdaw', 'info', 0, '2025-10-30 08:57:53'),
(535, 116, 'attorney', 'New Schedule Assigned', 'A new Hearing has been scheduled for you by admin: Opiña, Leif Laiglon Abriz on 2025-10-31 from 11:32 to 12:02 at dwadaw', 'info', 0, '2025-10-30 14:32:57'),
(536, 115, 'client', 'New Schedule Created', 'A new Hearing has been scheduled for you by admin: Opiña, Leif Laiglon Abriz on 2025-10-31 from 11:32 to 12:02 at dwadaw', 'info', 0, '2025-10-30 14:32:57'),
(537, 115, 'client', 'Message Seen', 'Your attorney has seen your conversation.', 'info', 0, '2025-10-30 15:05:52'),
(538, 115, 'client', 'New Message Received', 'You received a new message from attorney: dawdw, dawd dawd - dawdawdaw', 'info', 0, '2025-10-30 15:05:55'),
(539, 115, 'client', 'Case Status Updated', 'Your case \'dawdwa\' status has been updated to: Active', 'info', 0, '2025-10-30 15:18:59'),
(540, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Active', 'info', 0, '2025-10-30 15:42:17'),
(541, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Active', 'info', 0, '2025-10-30 15:49:13'),
(542, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Active', 'info', 0, '2025-10-30 15:49:19'),
(543, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Pending', 'info', 0, '2025-10-30 15:50:46'),
(544, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Active', 'info', 0, '2025-10-30 15:50:55'),
(545, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Active', 'info', 0, '2025-10-30 15:51:04'),
(546, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Active', 'info', 0, '2025-10-30 15:51:09'),
(547, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Active', 'info', 0, '2025-10-30 15:56:31'),
(548, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Closed', 'info', 0, '2025-10-30 15:56:47'),
(549, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Pending', 'info', 0, '2025-10-30 16:36:58'),
(550, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Pending', 'info', 0, '2025-10-30 16:38:23'),
(551, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Pending', 'info', 0, '2025-10-30 16:38:51'),
(552, 115, 'client', 'Case Status Updated', 'Your case \'dawdaw\' status has been updated to: Pending', 'info', 0, '2025-10-30 16:40:12'),
(553, 116, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Cancelled\' by Opiña, Leif Laiglon Abriz on 2025-10-31 from 11:32:00 to 12:02:00 at dwadaw', 'info', 0, '2025-10-30 17:18:43'),
(554, 115, 'client', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Cancelled\' by Opiña, Leif Laiglon Abriz on 2025-10-31 from 11:32:00 to 12:02:00 at dwadaw', 'info', 0, '2025-10-30 17:18:43'),
(555, 118, 'employee', 'New Client Request', 'Client dawdaw, dadaw dawd has submitted a new messaging request (ID: REQ-20251031-0120-5400). Please review and process the request.', 'info', 1, '2025-10-31 15:54:03'),
(556, 118, 'employee', 'New Client Request', 'Client dawdaw, dadaw dawd has submitted a new messaging request (ID: REQ-20251031-0120-2347). Please review and process the request.', 'info', 1, '2025-10-31 16:02:24'),
(557, 120, 'client', 'Request Rejected', 'Your request has been rejected. Reason: dawdawd', 'error', 0, '2025-10-31 16:02:56'),
(558, 118, 'employee', 'New Client Request', 'Client dawdaw, dadaw dawd has submitted a new messaging request (ID: REQ-20251031-0120-4394). Please review and process the request.', 'info', 1, '2025-10-31 16:05:51'),
(559, 120, 'client', 'Request Rejected', 'Your request has been rejected. Reason: dawd assddddddddddddddddddddddddddd sdaas', 'error', 0, '2025-10-31 16:05:58'),
(560, 118, 'employee', 'New Client Request', 'Client dawdaw, dadaw dawd has submitted a new messaging request (ID: REQ-20251031-0120-4576). Please review and process the request.', 'info', 1, '2025-10-31 16:08:47'),
(561, 120, 'client', 'Request Rejected', 'Your request has been rejected. Reason: dawdawda', 'error', 0, '2025-10-31 16:08:54'),
(562, 118, 'employee', 'New Client Request', 'Client dawdaw, dadaw dawd has submitted a new messaging request (ID: REQ-20251031-0120-5882). Please review and process the request.', 'info', 1, '2025-10-31 16:10:25'),
(563, 120, 'client', 'Request Rejected', 'Your request has been rejected. Reason: dawdawdawdaw', 'error', 0, '2025-10-31 16:10:31'),
(564, 1, 'attorney', 'New Schedule Assigned', 'A new Free Legal Advice has been scheduled for you by employee:  on 2025-11-04 from 12:42 to 13:12 at dawd', 'info', 1, '2025-11-03 03:42:20'),
(565, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-11-04 from 12:42:00 to 13:12:00 at dawd', 'info', 1, '2025-11-03 03:42:47'),
(566, 1, 'attorney', 'New Schedule Assigned', 'A new Appointment has been scheduled for you by employee:  on 2025-11-05 from 12:43 to 13:13 at asdasd', 'info', 1, '2025-11-03 03:44:34'),
(567, 1, 'attorney', 'New Schedule Assigned', 'A new Appointment has been scheduled for you by employee: Employee on 2025-11-07 from 12:48 to 13:18 at dawdaw', 'info', 1, '2025-11-03 03:48:19'),
(568, 1, 'attorney', 'New Schedule Assigned', 'A new Free Legal Advice has been scheduled for you by employee: Employee on 2025-11-04 from 12:58 to 13:28 at dawdwa', 'info', 1, '2025-11-03 03:58:12'),
(569, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-11-04 from 12:58:00 to 13:28:00 at dawdwa', 'info', 1, '2025-11-03 03:58:26'),
(570, 1, 'attorney', 'New Schedule Assigned', 'A new Free Legal Advice has been scheduled for you by employee: Employee on 2025-11-04 from 16:25 to 16:55 at dawdadwa', 'info', 1, '2025-11-03 04:25:33'),
(571, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-11-04 from 16:25:00 to 16:55:00 at dawdadwa', 'info', 1, '2025-11-03 04:27:10'),
(572, 1, 'attorney', 'New Schedule Assigned', 'A new Appointment has been scheduled for you by employee: Employee on 2025-11-04 from 15:38 to 16:08 at dwad', 'info', 1, '2025-11-03 04:39:06'),
(573, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-11-04 from 15:38:00 to 16:08:00 at dwad', 'info', 1, '2025-11-03 04:39:55'),
(574, 1, 'attorney', 'New Schedule Assigned', 'A new Appointment has been scheduled for you by employee: Employee on 2025-11-05 from 13:06 to 13:36 at dwadwa', 'info', 1, '2025-11-03 05:06:44'),
(575, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-11-05 from 13:06:00 to 13:36:00 at dwadwa', 'info', 1, '2025-11-03 05:07:53'),
(576, 1, 'attorney', 'New Schedule Assigned', 'A new Free Legal Advice has been scheduled for you by employee: Employee on 2025-11-04 from 14:59 to 15:29 at dawdwa', 'info', 1, '2025-11-03 05:59:39'),
(577, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by  on 2025-11-04 from 14:59:00 to 15:29:00 at dawdwa', 'info', 1, '2025-11-03 06:02:49'),
(578, 1, 'attorney', 'New Schedule Assigned', 'A new Appointment has been scheduled for you by employee: Employee on 2025-11-05 from 15:16 to 15:46 at dawdaw', 'info', 1, '2025-11-03 06:16:34'),
(579, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-11-05 from 15:16:00 to 15:46:00 at dawdaw', 'info', 1, '2025-11-03 06:18:08'),
(580, 1, 'attorney', 'New Schedule Assigned', 'A new Free Legal Advice has been scheduled for you by employee: Employee on 2025-11-04 from 14:19 to 14:49 at dawdaw', 'info', 1, '2025-11-03 06:19:13'),
(581, 1, 'attorney', 'Schedule Status Updated', 'Schedule \'\' status has been updated to \'Completed\' by Opiña, Leif Laiglon Abriz on 2025-11-04 from 14:19:00 to 14:49:00 at dawdaw', 'info', 1, '2025-11-03 06:19:27');

-- --------------------------------------------------------

--
-- Table structure for table `password_history`
--

CREATE TABLE `password_history` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `changed_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `user_colors`
--

CREATE TABLE `user_colors` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `user_type` enum('admin','attorney','client','employee') NOT NULL,
  `schedule_card_color` varchar(7) NOT NULL COMMENT 'Hex color for schedule cards',
  `calendar_event_color` varchar(7) NOT NULL COMMENT 'Hex color for calendar events',
  `color_name` varchar(50) DEFAULT NULL COMMENT 'Human readable color name',
  `is_active` tinyint(1) DEFAULT 1 COMMENT '1 if color is in use, 0 if freed',
  `assigned_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `freed_at` timestamp NULL DEFAULT NULL COMMENT 'When color was freed due to user deletion'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_colors`
--

INSERT INTO `user_colors` (`id`, `user_id`, `user_type`, `schedule_card_color`, `calendar_event_color`, `color_name`, `is_active`, `assigned_at`, `freed_at`) VALUES
(0, 1, 'admin', '#E6B0AA', '#800000', 'Admin Maroon', 1, '2025-10-04 15:44:05', NULL),
(0, 2, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-04 15:46:15', NULL),
(0, 3, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-04 15:47:36', NULL),
(0, 7, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-05 06:39:26', NULL),
(0, 8, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-05 06:40:12', NULL),
(0, 12, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-06 05:54:19', NULL),
(0, 13, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-06 05:55:26', NULL),
(0, 17, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-07 09:47:14', NULL),
(0, 19, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-07 09:50:58', NULL),
(0, 22, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-08 01:10:33', NULL),
(0, 23, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-08 01:11:25', NULL),
(0, 1, 'admin', '#E6B0AA', '#800000', 'Admin Maroon', 1, '2025-10-04 15:44:05', NULL),
(0, 2, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-04 15:46:15', NULL),
(0, 3, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-04 15:47:36', NULL),
(0, 7, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-05 06:39:26', NULL),
(0, 8, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-05 06:40:12', NULL),
(0, 12, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-06 05:54:19', NULL),
(0, 13, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-06 05:55:26', NULL),
(0, 17, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-07 09:47:14', NULL),
(0, 19, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-07 09:50:58', NULL),
(0, 22, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-08 01:10:33', NULL),
(0, 23, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-08 01:11:25', NULL),
(0, 27, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-10 16:21:18', NULL),
(0, 28, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-10 18:45:25', NULL),
(0, 35, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-12 08:40:06', NULL),
(0, 36, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-14 11:51:36', NULL),
(0, 58, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-24 20:11:16', NULL),
(0, 70, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-25 06:42:29', NULL),
(0, 73, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-26 05:45:11', NULL),
(0, 74, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-26 05:49:57', NULL),
(0, 98, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-28 03:00:50', NULL),
(0, 103, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-28 05:48:34', NULL),
(0, 104, 'attorney', '#90EE90', '#008000', 'Attorney Light Green', 1, '2025-10-28 05:50:09', NULL),
(0, 108, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-28 20:24:25', NULL),
(0, 116, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-29 13:22:10', NULL),
(0, 119, 'attorney', '#ADD8E6', '#87CEEB', 'Attorney Sky Blue', 1, '2025-10-31 15:07:40', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `user_form`
--

CREATE TABLE `user_form` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `profile_image` varchar(255) DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `email` varchar(100) NOT NULL,
  `phone_number` varchar(20) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `user_type` enum('admin','attorney','client','employee') DEFAULT 'client',
  `login_attempts` int(11) DEFAULT 0,
  `last_failed_login` timestamp NULL DEFAULT NULL,
  `account_locked` tinyint(1) DEFAULT 0,
  `first_login` tinyint(1) DEFAULT 1,
  `waiver_accepted` tinyint(1) DEFAULT 0,
  `password_changed` tinyint(1) DEFAULT 0,
  `lockout_until` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_by` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_form`
--

INSERT INTO `user_form` (`id`, `name`, `profile_image`, `last_login`, `email`, `phone_number`, `password`, `user_type`, `login_attempts`, `last_failed_login`, `account_locked`, `first_login`, `waiver_accepted`, `password_changed`, `lockout_until`, `created_at`, `created_by`) VALUES
(1, 'Opiña, Leif Laiglon Abriz', 'uploads/admin/1_1759828076_093758914f59d137.jpg', '2025-10-31 21:49:43', 'leifopina25@gmail.com', '09283262333', '$2y$10$VFyQmcbe/.cdjVY7DWDxS.40nxC8.wRe7pBFX5zVoYxPHAM2DzrA2', 'admin', 0, NULL, 0, 1, 0, 0, NULL, '2025-10-04 18:16:17', NULL);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admin_messages`
--
ALTER TABLE `admin_messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `admin_id` (`admin_id`),
  ADD KEY `recipient_id` (`recipient_id`);

--
-- Indexes for table `announcements`
--
ALTER TABLE `announcements`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `attorney_cases`
--
ALTER TABLE `attorney_cases`
  ADD PRIMARY KEY (`id`),
  ADD KEY `attorney_id` (`attorney_id`),
  ADD KEY `client_id` (`client_id`);

--
-- Indexes for table `attorney_documents`
--
ALTER TABLE `attorney_documents`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `attorney_document_activity`
--
ALTER TABLE `attorney_document_activity`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `attorney_messages`
--
ALTER TABLE `attorney_messages`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `audit_trail`
--
ALTER TABLE `audit_trail`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `timestamp` (`timestamp`);

--
-- Indexes for table `case_documents`
--
ALTER TABLE `case_documents`
  ADD PRIMARY KEY (`id`),
  ADD KEY `case_id` (`case_id`),
  ADD KEY `uploaded_by` (`uploaded_by`);

--
-- Indexes for table `case_schedules`
--
ALTER TABLE `case_schedules`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `client_attorney_assignments`
--
ALTER TABLE `client_attorney_assignments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `conversation_id` (`conversation_id`),
  ADD KEY `client_id` (`client_id`),
  ADD KEY `attorney_id` (`attorney_id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `client_attorney_conversations`
--
ALTER TABLE `client_attorney_conversations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `assignment_id` (`assignment_id`),
  ADD KEY `client_id` (`client_id`),
  ADD KEY `attorney_id` (`attorney_id`);

--
-- Indexes for table `client_attorney_messages`
--
ALTER TABLE `client_attorney_messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `conversation_id` (`conversation_id`),
  ADD KEY `sender_id` (`sender_id`);

--
-- Indexes for table `client_document_generation`
--
ALTER TABLE `client_document_generation`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `request_id` (`request_id`),
  ADD KEY `idx_client_id` (`client_id`),
  ADD KEY `idx_status` (`status`),
  ADD KEY `idx_document_type` (`document_type`),
  ADD KEY `idx_submitted_at` (`submitted_at`),
  ADD KEY `reviewed_by` (`reviewed_by`);

--
-- Indexes for table `client_employee_conversations`
--
ALTER TABLE `client_employee_conversations`
  ADD PRIMARY KEY (`id`),
  ADD KEY `request_form_id` (`request_form_id`),
  ADD KEY `client_id` (`client_id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `client_employee_messages`
--
ALTER TABLE `client_employee_messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `conversation_id` (`conversation_id`),
  ADD KEY `sender_id` (`sender_id`);

--
-- Indexes for table `client_messages`
--
ALTER TABLE `client_messages`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `client_request_form`
--
ALTER TABLE `client_request_form`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `request_id` (`request_id`),
  ADD KEY `client_id` (`client_id`),
  ADD KEY `status` (`status`);

--
-- Indexes for table `efiling_history`
--
ALTER TABLE `efiling_history`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employee_documents`
--
ALTER TABLE `employee_documents`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employee_document_activity`
--
ALTER TABLE `employee_document_activity`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employee_messages`
--
ALTER TABLE `employee_messages`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employee_request_reviews`
--
ALTER TABLE `employee_request_reviews`
  ADD PRIMARY KEY (`id`),
  ADD KEY `request_form_id` (`request_form_id`),
  ADD KEY `employee_id` (`employee_id`);

--
-- Indexes for table `maintenance_settings`
--
ALTER TABLE `maintenance_settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `notifications`
--
ALTER TABLE `notifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `is_read` (`is_read`);

--
-- Indexes for table `password_history`
--
ALTER TABLE `password_history`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `user_form`
--
ALTER TABLE `user_form`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admin_messages`
--
ALTER TABLE `admin_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `announcements`
--
ALTER TABLE `announcements`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `attorney_cases`
--
ALTER TABLE `attorney_cases`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=58;

--
-- AUTO_INCREMENT for table `attorney_documents`
--
ALTER TABLE `attorney_documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=150;

--
-- AUTO_INCREMENT for table `attorney_document_activity`
--
ALTER TABLE `attorney_document_activity`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=50;

--
-- AUTO_INCREMENT for table `attorney_messages`
--
ALTER TABLE `attorney_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `audit_trail`
--
ALTER TABLE `audit_trail`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13409;

--
-- AUTO_INCREMENT for table `case_documents`
--
ALTER TABLE `case_documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=35;

--
-- AUTO_INCREMENT for table `case_schedules`
--
ALTER TABLE `case_schedules`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=97;

--
-- AUTO_INCREMENT for table `client_attorney_assignments`
--
ALTER TABLE `client_attorney_assignments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=41;

--
-- AUTO_INCREMENT for table `client_attorney_conversations`
--
ALTER TABLE `client_attorney_conversations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=41;

--
-- AUTO_INCREMENT for table `client_attorney_messages`
--
ALTER TABLE `client_attorney_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=61;

--
-- AUTO_INCREMENT for table `client_document_generation`
--
ALTER TABLE `client_document_generation`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=66;

--
-- AUTO_INCREMENT for table `client_employee_conversations`
--
ALTER TABLE `client_employee_conversations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=41;

--
-- AUTO_INCREMENT for table `client_employee_messages`
--
ALTER TABLE `client_employee_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=34;

--
-- AUTO_INCREMENT for table `client_messages`
--
ALTER TABLE `client_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `client_request_form`
--
ALTER TABLE `client_request_form`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=62;

--
-- AUTO_INCREMENT for table `efiling_history`
--
ALTER TABLE `efiling_history`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=66;

--
-- AUTO_INCREMENT for table `employee_documents`
--
ALTER TABLE `employee_documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=113;

--
-- AUTO_INCREMENT for table `employee_document_activity`
--
ALTER TABLE `employee_document_activity`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=38;

--
-- AUTO_INCREMENT for table `employee_messages`
--
ALTER TABLE `employee_messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `employee_request_reviews`
--
ALTER TABLE `employee_request_reviews`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=50;

--
-- AUTO_INCREMENT for table `maintenance_settings`
--
ALTER TABLE `maintenance_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=582;

--
-- AUTO_INCREMENT for table `password_history`
--
ALTER TABLE `password_history`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `user_form`
--
ALTER TABLE `user_form`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=121;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `case_documents`
--
ALTER TABLE `case_documents`
  ADD CONSTRAINT `case_documents_ibfk_1` FOREIGN KEY (`case_id`) REFERENCES `attorney_cases` (`id`),
  ADD CONSTRAINT `case_documents_ibfk_2` FOREIGN KEY (`uploaded_by`) REFERENCES `user_form` (`id`);

--
-- Constraints for table `client_attorney_assignments`
--
ALTER TABLE `client_attorney_assignments`
  ADD CONSTRAINT `client_attorney_assignments_ibfk_1` FOREIGN KEY (`conversation_id`) REFERENCES `client_employee_conversations` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_attorney_assignments_ibfk_2` FOREIGN KEY (`client_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_attorney_assignments_ibfk_3` FOREIGN KEY (`employee_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_attorney_assignments_ibfk_4` FOREIGN KEY (`attorney_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `client_attorney_conversations`
--
ALTER TABLE `client_attorney_conversations`
  ADD CONSTRAINT `client_attorney_conversations_ibfk_1` FOREIGN KEY (`assignment_id`) REFERENCES `client_attorney_assignments` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_attorney_conversations_ibfk_2` FOREIGN KEY (`client_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_attorney_conversations_ibfk_3` FOREIGN KEY (`attorney_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `client_attorney_messages`
--
ALTER TABLE `client_attorney_messages`
  ADD CONSTRAINT `client_attorney_messages_ibfk_1` FOREIGN KEY (`conversation_id`) REFERENCES `client_attorney_conversations` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_attorney_messages_ibfk_2` FOREIGN KEY (`sender_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `client_document_generation`
--
ALTER TABLE `client_document_generation`
  ADD CONSTRAINT `client_document_generation_ibfk_1` FOREIGN KEY (`client_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_document_generation_ibfk_2` FOREIGN KEY (`reviewed_by`) REFERENCES `user_form` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `client_employee_conversations`
--
ALTER TABLE `client_employee_conversations`
  ADD CONSTRAINT `client_employee_conversations_ibfk_1` FOREIGN KEY (`request_form_id`) REFERENCES `client_request_form` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_employee_conversations_ibfk_2` FOREIGN KEY (`client_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_employee_conversations_ibfk_3` FOREIGN KEY (`employee_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `client_employee_messages`
--
ALTER TABLE `client_employee_messages`
  ADD CONSTRAINT `client_employee_messages_ibfk_1` FOREIGN KEY (`conversation_id`) REFERENCES `client_employee_conversations` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `client_employee_messages_ibfk_2` FOREIGN KEY (`sender_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `client_request_form`
--
ALTER TABLE `client_request_form`
  ADD CONSTRAINT `client_request_form_ibfk_1` FOREIGN KEY (`client_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `employee_request_reviews`
--
ALTER TABLE `employee_request_reviews`
  ADD CONSTRAINT `employee_request_reviews_ibfk_1` FOREIGN KEY (`request_form_id`) REFERENCES `client_request_form` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `employee_request_reviews_ibfk_2` FOREIGN KEY (`employee_id`) REFERENCES `user_form` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
