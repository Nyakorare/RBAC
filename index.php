<?php
session_start();
include 'db.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT id, username FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username']; // Store username in session
        header("Location: dashboard.php");
    } else {
        echo "<script>alert('Invalid username or password.');</script>";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RoleWrite</title>
    <!-- Tailwind CSS -->
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <!-- Custom CSS -->
    <link rel="stylesheet" href="index.css">
    <!-- GSAP for animations -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.9.1/gsap.min.js"></script>
</head>
<body class="bg-gradient-to-r from-blue-500 to-purple-600 min-h-screen flex items-center justify-center">
    <div class="login-container p-8 max-w-md w-full text-center">
        <h1 class="text-4xl font-bold text-white mb-4">RoleWrite</h1>
        <p class="text-gray-200 mb-8">Login to access your dashboard.</p>
        <form method="post" class="space-y-6">
            <input type="text" name="username" placeholder="Username" required
                   class="input-field w-full px-4 py-3 rounded-lg bg-white bg-opacity-20 text-white placeholder-gray-300 focus:outline-none focus:bg-opacity-30">
            <input type="password" name="password" placeholder="Password" required
                   class="input-field w-full px-4 py-3 rounded-lg bg-white bg-opacity-20 text-white placeholder-gray-300 focus:outline-none focus:bg-opacity-30">
            <button type="submit" class="w-full bg-white text-blue-600 py-3 rounded-lg font-semibold hover:bg-opacity-90 transition duration-300">
                Login
            </button>
        </form>
        <p class="text-gray-200 mt-6">Don't have an account? <a href="#" class="text-white font-semibold hover:underline">Sign up</a></p>
    </div>

    <script>
        // GSAP Animations
        gsap.from(".login-container", {
            duration: 1,
            y: -50,
            opacity: 0,
            ease: "power3.out"
        });

        gsap.from("h1", {
            duration: 1,
            y: -30,
            opacity: 0,
            delay: 0.5,
            ease: "power3.out"
        });

        gsap.from("p", {
            duration: 1,
            y: -20,
            opacity: 0,
            delay: 0.8,
            ease: "power3.out"
        });

        gsap.from(".input-field", {
            duration: 1,
            x: -50,
            opacity: 0,
            stagger: 0.2,
            delay: 1,
            ease: "power3.out"
        });

        gsap.from("button", {
            duration: 1,
            y: 50,
            opacity: 0,
            delay: 1.5,
            ease: "power3.out"
        });
    </script>
</body>
</html>