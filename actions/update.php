<?php
session_start();
include '../db.php';

// Redirect if user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit();
}

// Check if the user has permission to update content
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT p.name FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id JOIN roles r ON rp.role_id = r.id JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ? AND p.name = 'Update content'");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 0) {
    die("You do not have permission to update content.");
}

// Fetch the content to be updated
if (isset($_GET['id'])) {
    $content_id = $_GET['id'];
    $stmt = $conn->prepare("SELECT * FROM content WHERE id = ?");
    $stmt->bind_param("i", $content_id);
    $stmt->execute();
    $content = $stmt->get_result()->fetch_assoc();
}

// Update the content
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['title']) && isset($_POST['description'])) {
    $content_id = $_POST['content_id'];
    $title = $_POST['title'];
    $description = $_POST['description'];

    $stmt = $conn->prepare("UPDATE content SET title = ?, description = ? WHERE id = ?");
    $stmt->bind_param("ssi", $title, $description, $content_id);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        header("Location: ../dashboard.php?message=Content+updated+successfully");
    } else {
        header("Location: ../dashboard.php?error=Failed+to+update+content");
    }
    exit();
}
?>

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="../style.css">
    <title>RoleWrite - Update Blog</title>
</head>
<body>
    <div class="update-container">
        <h1>Update Content</h1>
        <form method="POST">
            <input type="hidden" name="content_id" value="<?php echo $content['id']; ?>">
            <input type="text" name="title" value="<?php echo htmlspecialchars($content['title']); ?>" required>
            <textarea name="description" required><?php echo htmlspecialchars($content['description']); ?></textarea>
            <button type="submit" class="action-button">Update</button>
        </form>
        <a href="../dashboard.php" class="action-button">Back to Dashboard</a>
    </div>
</body>
</html>