<?php
session_start();
include '../db.php';

// Redirect if user is not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../index.php");
    exit();
}

// Fetch the user's role and permissions
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT r.name AS role, p.name AS permission FROM users u JOIN user_roles ur ON u.id = ur.user_id JOIN roles r ON ur.role_id = r.id JOIN role_permissions rp ON r.id = rp.role_id JOIN permissions p ON rp.permission_id = p.id WHERE u.id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

$role = '';
$permissions = [];
while ($row = $result->fetch_assoc()) {
    if (empty($role)) {
        $role = $row['role'];
    }
    $permissions[] = $row['permission'];
}

// Check if the user has permission to access user data
if (!in_array('Access user data', $permissions)) {
    die("You do not have permission to access user data.");
}

// Fetch all users and their roles (including role_id)
$users = $conn->query("SELECT u.id, u.username, r.id AS role_id, r.name AS role FROM users u JOIN user_roles ur ON u.id = ur.user_id JOIN roles r ON ur.role_id = r.id");

// Fetch all permissions
$permissionsList = $conn->query("SELECT * FROM permissions");

// Fetch role permissions
$rolePermissions = [];
$rolePermissionsResult = $conn->query("SELECT role_id, permission_id FROM role_permissions");
while ($row = $rolePermissionsResult->fetch_assoc()) {
    $rolePermissions[$row['role_id']][] = $row['permission_id'];
}

// Fetch the number of content items published by each user
$userContentCounts = [];
$usersForContentCount = $conn->query("SELECT * FROM users");
while ($user = $usersForContentCount->fetch_assoc()) {
    $userId = $user['id'];
    $stmt = $conn->prepare("SELECT COUNT(*) AS content_count FROM content WHERE user_id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $contentCountResult = $stmt->get_result();
    $contentCount = $contentCountResult->fetch_assoc()['content_count'];
    $userContentCounts[$userId] = $contentCount;
}
?>

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="../style.css">
    <title>RoleWrite - User Data</title>
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
                <?php if (in_array('Access user data', $permissions)): ?>
                    <li><a href="access.php">Access User Data</a></li>
                <?php endif; ?>
                <?php if (in_array('Change system settings', $permissions)): ?>
                    <li><a href="change.php">Change System Settings</a></li>
                <?php endif; ?>
                <li><a href="../logout.php" class="logout-button">Logout</a></li>
            </ul>
        </nav>
    </header>

    <!-- User Data Container -->
    <div class="user-data-container">
        <h1>User Data Permission</h1>

        <!-- Only show the User Data Permission Table if the user is an Admin -->
        <?php if ($role === 'Admin'): ?>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <?php while ($permission = $permissionsList->fetch_assoc()): ?>
                            <th><?php echo htmlspecialchars($permission['name']); ?></th>
                        <?php endwhile; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($user = $users->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['role']); ?></td>
                            <?php
                            // Reset permissions pointer
                            $permissionsList->data_seek(0);
                            while ($permission = $permissionsList->fetch_assoc()):
                                $hasPermission = isset($rolePermissions[$user['role_id']]) && in_array($permission['id'], $rolePermissions[$user['role_id']]);
                            ?>
                                <td><?php echo $hasPermission ? '✔' : '❌'; ?></td>
                            <?php endwhile; ?>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p>You do not have permission to view the User Data Permission Table.</p>
        <?php endif; ?>

        <!-- Content Published by Users Box -->
        <div class="content-count-box">
            <h2>Content Published by Users</h2>
            <table>
                <thead>
                    <tr>
                        <th>User ID</th>
                        <th>Username</th>
                        <th>Content Published</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($userContentCounts as $userId => $contentCount): ?>
                        <?php
                        // Fetch the username for the user ID
                        $stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
                        $stmt->bind_param("i", $userId);
                        $stmt->execute();
                        $usernameResult = $stmt->get_result();
                        $username = $usernameResult->fetch_assoc()['username'];
                        ?>
                        <tr>
                            <td><?php echo htmlspecialchars($userId); ?></td>
                            <td><?php echo htmlspecialchars($username); ?></td>
                            <td><?php echo htmlspecialchars($contentCount); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <a href="../dashboard.php" class="action-button">Back to Dashboard</a>
    </div>
</body>
</html>