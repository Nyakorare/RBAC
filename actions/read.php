<?php
session_start();
include '../db.php';

// Redirect if user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit();
}

// Check if the user has permission to read content
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT p.name FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id JOIN roles r ON rp.role_id = r.id JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ? AND p.name = 'Read content'");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 0) {
    die("You do not have permission to read content.");
}

// Fetch the content with the author's username
if (isset($_GET['id'])) {
    $content_id = $_GET['id'];
    $stmt = $conn->prepare("
        SELECT c.id, c.title, c.description, u.username AS author 
        FROM content c 
        JOIN users u ON c.author_id = u.id 
        WHERE c.id = ?
    ");
    $stmt->bind_param("i", $content_id);
    $stmt->execute();
    $content = $stmt->get_result()->fetch_assoc();
} else {
    die("Content ID not provided.");
}
?>

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="../read.css">
    <title>RoleWrite - Read Blog</title>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="welcome-message">
            <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
        </div>
        <!-- Navbar -->
        <nav class="navbar">
            <ul>
                <li><a href="../dashboard.php">Dashboard</a></li>
                <li><a href="access.php">Access User Data</a></li>
                <li><a href="change.php">Change User Settings</a></li>
                <li><a href="../logout.php" class="logout-button">Logout</a></li>
            </ul>
        </nav>
    </header>

    <!-- Read Content Container -->
    <div class="read-content-box">
        <div class="read-content-header">
            <h1><?php echo htmlspecialchars($content['title']); ?></h1>
            <p class="author">By: <?php echo htmlspecialchars($content['author']); ?></p>
        </div>
        <div class="read-content-body">
            <p><?php echo htmlspecialchars($content['description']); ?></p>
        </div>
        <div class="read-content-footer">
            <a href="../dashboard.php" class="action-button">Back to Dashboard</a>
        </div>
    </div>
</body>
</html>