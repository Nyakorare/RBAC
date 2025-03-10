<?php
session_start();
include '../db.php';

// Redirect if user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit();
}

// Check if the user has permission to create content
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT p.name FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id JOIN roles r ON rp.role_id = r.id JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ? AND p.name = 'Create content'");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 0) {
    die("You do not have permission to create content.");
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $title = $_POST['title'];
    $description = $_POST['description'];
    $author_id = $_SESSION['user_id']; // Get the author's ID from the session

    $stmt = $conn->prepare("INSERT INTO content (title, description, author_id) VALUES (?, ?, ?)");
    $stmt->bind_param("ssi", $title, $description, $author_id);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        header("Location: ../dashboard.php?message=Content+created+successfully");
    } else {
        header("Location: ../dashboard.php?error=Failed+to+create+content");
    }
    exit();
}

header("Location: ../dashboard.php");
?>