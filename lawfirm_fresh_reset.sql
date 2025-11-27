-- ------------------------------------------------------------
-- Fresh data reset for `lawfirm` database (excluding admin user)
-- Generated on 2025-11-11
-- ------------------------------------------------------------

START TRANSACTION;
SET FOREIGN_KEY_CHECKS = 0;

DELETE FROM `client_attorney_messages`;
ALTER TABLE `client_attorney_messages` AUTO_INCREMENT = 1;

DELETE FROM `client_employee_messages`;
ALTER TABLE `client_employee_messages` AUTO_INCREMENT = 1;

DELETE FROM `client_messages`;
ALTER TABLE `client_messages` AUTO_INCREMENT = 1;

DELETE FROM `document_request_comments`;
ALTER TABLE `document_request_comments` AUTO_INCREMENT = 1;

DELETE FROM `document_request_files`;
ALTER TABLE `document_request_files` AUTO_INCREMENT = 1;

DELETE FROM `attorney_document_activity`;
ALTER TABLE `attorney_document_activity` AUTO_INCREMENT = 1;

DELETE FROM `employee_document_activity`;
ALTER TABLE `employee_document_activity` AUTO_INCREMENT = 1;

DELETE FROM `case_documents`;
ALTER TABLE `case_documents` AUTO_INCREMENT = 1;

DELETE FROM `employee_request_reviews`;
ALTER TABLE `employee_request_reviews` AUTO_INCREMENT = 1;

DELETE FROM `client_attorney_conversations`;
ALTER TABLE `client_attorney_conversations` AUTO_INCREMENT = 1;

DELETE FROM `client_employee_conversations`;
ALTER TABLE `client_employee_conversations` AUTO_INCREMENT = 1;

DELETE FROM `client_attorney_assignments`;
ALTER TABLE `client_attorney_assignments` AUTO_INCREMENT = 1;

DELETE FROM `document_requests`;
ALTER TABLE `document_requests` AUTO_INCREMENT = 1;

DELETE FROM `client_document_generation`;
ALTER TABLE `client_document_generation` AUTO_INCREMENT = 1;

DELETE FROM `client_request_form`;
ALTER TABLE `client_request_form` AUTO_INCREMENT = 1;

DELETE FROM `attorney_documents`;
ALTER TABLE `attorney_documents` AUTO_INCREMENT = 1;

DELETE FROM `employee_documents`;
ALTER TABLE `employee_documents` AUTO_INCREMENT = 1;

DELETE FROM `case_schedules`;
ALTER TABLE `case_schedules` AUTO_INCREMENT = 1;

DELETE FROM `attorney_cases`;
ALTER TABLE `attorney_cases` AUTO_INCREMENT = 1;

DELETE FROM `admin_messages`;
ALTER TABLE `admin_messages` AUTO_INCREMENT = 1;

DELETE FROM `announcements`;
ALTER TABLE `announcements` AUTO_INCREMENT = 1;

DELETE FROM `attorney_messages`;
ALTER TABLE `attorney_messages` AUTO_INCREMENT = 1;

DELETE FROM `audit_trail`;
ALTER TABLE `audit_trail` AUTO_INCREMENT = 1;

DELETE FROM `available_colors`;
ALTER TABLE `available_colors` AUTO_INCREMENT = 1;

DELETE FROM `efiling_history`;
ALTER TABLE `efiling_history` AUTO_INCREMENT = 1;

DELETE FROM `employee_messages`;
ALTER TABLE `employee_messages` AUTO_INCREMENT = 1;

DELETE FROM `maintenance_settings`;
ALTER TABLE `maintenance_settings` AUTO_INCREMENT = 1;

DELETE FROM `notifications`;
ALTER TABLE `notifications` AUTO_INCREMENT = 1;

DELETE FROM `password_history`;
ALTER TABLE `password_history` AUTO_INCREMENT = 1;

DELETE FROM `user_colors`;
ALTER TABLE `user_colors` AUTO_INCREMENT = 1;

DELETE FROM `user_form` WHERE `id` <> 1;

INSERT INTO `user_form` (
    `id`,
    `name`,
    `profile_image`,
    `last_login`,
    `email`,
    `phone_number`,
    `password`,
    `user_type`,
    `login_attempts`,
    `last_failed_login`,
    `account_locked`,
    `first_login`,
    `waiver_accepted`,
    `password_changed`,
    `lockout_until`,
    `created_at`,
    `created_by`
) VALUES (
    1,
    'Opiña, Leif Laiglon Abriz',
    'uploads/admin/1_1759828076_093758914f59d137.jpg',
    '2025-10-31 21:49:43',
    'leifopina25@gmail.com',
    '09283262333',
    '$2y$10$VFyQmcbe/.cdjVY7DWDxS.40nxC8.wRe7pBFX5zVoYxPHAM2DzrA2',
    'admin',
    0,
    NULL,
    0,
    1,
    0,
    0,
    NULL,
    '2025-10-04 18:16:17',
    NULL
) ON DUPLICATE KEY UPDATE
    `name` = VALUES(`name`),
    `profile_image` = VALUES(`profile_image`),
    `last_login` = VALUES(`last_login`),
    `email` = VALUES(`email`),
    `phone_number` = VALUES(`phone_number`),
    `password` = VALUES(`password`),
    `user_type` = VALUES(`user_type`),
    `login_attempts` = VALUES(`login_attempts`),
    `last_failed_login` = VALUES(`last_failed_login`),
    `account_locked` = VALUES(`account_locked`),
    `first_login` = VALUES(`first_login`),
    `waiver_accepted` = VALUES(`waiver_accepted`),
    `password_changed` = VALUES(`password_changed`),
    `lockout_until` = VALUES(`lockout_until`),
    `created_at` = VALUES(`created_at`),
    `created_by` = VALUES(`created_by`);

ALTER TABLE `user_form` AUTO_INCREMENT = 2;

SET FOREIGN_KEY_CHECKS = 1;
COMMIT;

