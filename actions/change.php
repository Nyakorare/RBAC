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

// Check if the user has permission to change system settings
if (!in_array('Change system settings', $permissions)) {
    die("You do not have permission to change user settings.");
}

// Fetch all roles except Admin and IT Support
$roles = $conn->query("SELECT * FROM roles WHERE name NOT IN ('Admin', 'IT Support')");

// Fetch all permissions except "Change system settings"
$permissionsList = $conn->query("SELECT * FROM permissions WHERE name != 'Change system settings'");

// Fetch existing permissions for the selected role (if any)
$existingPermissions = [];
if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['role_id'])) {
    $role_id = $_GET['role_id'];
    $stmt = $conn->prepare("SELECT permission_id FROM role_permissions WHERE role_id = ?");
    $stmt->bind_param("i", $role_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $existingPermissions[] = $row['permission_id'];
    }
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $role_id = $_POST['role_id'];
    $permission_ids = $_POST['permissions'];

    // Delete existing permissions for the role
    $stmt = $conn->prepare("DELETE FROM role_permissions WHERE role_id = ?");
    $stmt->bind_param("i", $role_id);
    $stmt->execute();

    // Insert new permissions for the role
    foreach ($permission_ids as $permission_id) {
        $stmt = $conn->prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)");
        $stmt->bind_param("ii", $role_id, $permission_id);
        $stmt->execute();
    }

    echo "<p>Permissions updated successfully!</p>";
}
?>

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="../style.css">
    <title>RoleWrite - User Settings</title>
    <script>
        function confirmUpdate() {
            const firstConfirmation = confirm("Are you sure you want to update permissions?");
            if (firstConfirmation) {
                const secondConfirmation = confirm("This action cannot be undone. Confirm again to proceed.");
                if (secondConfirmation) {
                    return true; // Proceed with form submission
                }
            }
            return false; // Cancel form submission
        }

        function fetchPermissions(roleId) {
            window.location.href = `change.php?role_id=${roleId}`;
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
                <li><a href="../dashboard.php">Dashboard</a></li>
                <?php if (in_array('Access user data', $permissions)): ?>
                    <li><a href="access.php">Access User Data</a></li>
                <?php endif; ?>
                <?php if (in_array('Change system settings', $permissions)): ?>
                    <li><a href="change.php">Change User Settings</a></li>
                <?php endif; ?>
                <li><a href="../logout.php" class="logout-button">Logout</a></li>
            </ul>
        </nav>
    </header>

    <!-- Settings Container -->
    <div class="settings-container">
        <h1>Change User Settings</h1>
        <form method="POST" onsubmit="return confirmUpdate()">
            <label for="role_id">Select Role:</label>
            <select name="role_id" id="role_id" onchange="fetchPermissions(this.value)" required>
                <option value="">Select a role</option>
                <?php while ($role = $roles->fetch_assoc()): ?>
                    <option value="<?php echo $role['id']; ?>" <?php echo (isset($_GET['role_id']) && $_GET['role_id'] == $role['id']) ? 'selected' : ''; ?>>
                        <?php echo htmlspecialchars($role['name']); ?>
                    </option>
                <?php endwhile; ?>
            </select>

            <label>Select Permissions:</label>
            <?php while ($permission = $permissionsList->fetch_assoc()): ?>
                <div>
                    <input type="checkbox" name="permissions[]" value="<?php echo $permission['id']; ?>"
                        <?php echo in_array($permission['id'], $existingPermissions) ? 'checked' : ''; ?>>
                    <?php echo htmlspecialchars($permission['name']); ?>
                </div>
            <?php endwhile; ?>

            <button type="submit" class="action-button">Update Permissions</button>
        </form>
        <a href="../dashboard.php" class="action-button">Back to Dashboard</a>
    </div>
</body>
</html>