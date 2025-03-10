<?php
session_start();
include '../db.php';

// Redirect if user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit();
}

// Check if the user has permission to delete content
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT p.name FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id JOIN roles r ON rp.role_id = r.id JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ? AND p.name = 'Delete content'");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 0) {
    die("You do not have permission to delete content.");
}

// Delete the content
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['content_id'])) {
    $content_id = $_POST['content_id'];
    $stmt = $conn->prepare("DELETE FROM content WHERE id = ?");
    $stmt->bind_param("i", $content_id);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        header("Location: ../dashboard.php?message=Content+deleted+successfully");
    } else {
        header("Location: ../dashboard.php?error=Failed+to+delete+content");
    }
    exit();
}

header("Location: ../dashboard.php");
?>