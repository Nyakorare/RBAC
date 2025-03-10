<?php
session_start();
include 'db.php';

// Redirect to login if user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$user_id = $_SESSION['user_id'];

// Fetch the user's role
$stmt = $conn->prepare("SELECT r.name FROM users u JOIN user_roles ur ON u.id = ur.user_id JOIN roles r ON ur.role_id = r.id WHERE u.id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows == 0) {
    die("User role not found.");
}

$role = $result->fetch_assoc()['name'];

// Fetch the user's permissions
$stmt = $conn->prepare("SELECT p.name FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id JOIN roles r ON rp.role_id = r.id WHERE r.name = ?");
$stmt->bind_param("s", $role);
$stmt->execute();
$permissions = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

$permissionNames = array_column($permissions, 'name');

// Fetch all content from the database with author usernames
$contentResult = $conn->query("
    SELECT c.id, c.title, c.description, c.author_id, u.username AS author 
    FROM content c 
    JOIN users u ON c.author_id = u.id
");
$content = $contentResult->fetch_all(MYSQLI_ASSOC);
?>

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="style.css">
    <title>RoleWrite - Dashboard</title>
    <script>
        function togglePermissions() {
            const permissionsDiv = document.getElementById('permissions');
            if (permissionsDiv.style.display === 'none') {
                permissionsDiv.style.display = 'block';
            } else {
                permissionsDiv.style.display = 'none';
            }
        }

        function toggleSection(sectionId, event) {
            event.preventDefault(); // Prevent default anchor link behavior
            const section = document.getElementById(sectionId);
            if (section.style.display === 'none') {
                section.style.display = 'block';
            } else {
                section.style.display = 'none';
            }
        }
    </script>
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
                <li><a href="#content" onclick="toggleSection('content-list', event)">Content</a></li>
                <?php if (in_array('Create content', $permissionNames)): ?>
                    <li><a href="#create-content" onclick="toggleSection('create-content-form', event)">Create Content</a></li>
                <?php endif; ?>
                <?php if (in_array('Access user data', $permissionNames)): ?>
                    <li><a href="actions/access.php">Access User Data</a></li>
                <?php endif; ?>
                <?php if (in_array('Change system settings', $permissionNames)): ?>
                    <li><a href="actions/change.php">Change User Settings</a></li>
                <?php endif; ?>
                <li><a href="logout.php" class="logout-button">Logout</a></li>
            </ul>
        </nav>
    </header>

    <!-- Dashboard Container -->
    <div class="dashboard-container">
        <button onclick="togglePermissions()" class="action-button">Show Permissions</button>
        <div id="permissions" class="permissions" style="display: none;">
            <h2>Your Permissions:</h2>
            <ul>
                <?php foreach ($permissionNames as $permission): ?>
                    <li><?php echo htmlspecialchars($permission); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>

        <!-- Content Section -->
        <section id="content-section" class="content-section">
            <h2 onclick="toggleSection('content-list', event)">Content</h2>
            <div id="content-list" class="content-list" style="display: none;">
                <?php if (empty($content)): ?>
                    <p>No content available.</p>
                <?php else: ?>
                    <ul>
                        <?php foreach ($content as $item): ?>
                            <li>
                                <strong><?php echo htmlspecialchars($item['title']); ?></strong>
                                <p>By: <?php echo htmlspecialchars($item['author']); ?></p>
                                <div class="content-preview">
                                    <p><?php echo explode(' ', htmlspecialchars($item['description']))[0]; ?>...</p>
                                    <a href="actions/read.php?id=<?php echo $item['id']; ?>" class="action-button see-more-button">See More</a>
                                </div>
                                <?php if (in_array('Update content', $permissionNames)): ?>
                                    <a href="actions/update.php?id=<?php echo $item['id']; ?>" class="action-button update-button">Update</a>
                                <?php endif; ?>
                                <?php if (in_array('Delete content', $permissionNames)): ?>
                                    <form action="actions/delete.php" method="POST" style="display:inline;">
                                        <input type="hidden" name="content_id" value="<?php echo $item['id']; ?>">
                                        <button type="submit" class="action-button delete-button">Delete</button>
                                    </form>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
        </section>

        <!-- Create Content Section -->
        <?php if (in_array('Create content', $permissionNames)): ?>
            <section id="create-content-section" class="create-content-section">
                <h2 onclick="toggleSection('create-content-form', event)">Create Content</h2>
                <div id="create-content-form" class="create-content-form" style="display: none;">
                    <form action="actions/create.php" method="POST">
                        <input type="text" name="title" placeholder="Title" required>
                        <textarea name="description" placeholder="Description" required></textarea>
                        <button type="submit" class="action-button">Create</button>
                    </form>
                </div>
            </section>
        <?php endif; ?>
    </div>
</body>
</html>