<?php
session_start();

// Database connection
$servername = "localhost";
$username = "root";
$password = "root123";
$dbname = "neet_institute";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // SQL query to fetch user with matching email
    $sql = "SELECT * FROM users WHERE email = ?";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("s", $email); // Bind the email parameter
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if user exists
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();

            // Verify the password
            if (password_verify($password, $user['password'])) {
                // Successful login, set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username']; // You can store the username if needed
                $_SESSION['email'] = $user['email'];

                // Redirect to dashboard
                header("Location: dashboard.php");
                exit();
            } else {
                // Incorrect password
                $_SESSION['login_error'] = "Incorrect password. Please try again.";
            }
        } else {
            // No user found
            $_SESSION['login_error'] = "No account found with that email.";
        }
        $stmt->close();
    } else {
        // Error in preparing SQL statement
        $_SESSION['login_error'] = "An error occurred. Please try again later.";
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In - NEET Institute</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="form-container">
        <h2>Log In</h2>
        <p>Welcome back! Please log in to access your dashboard.</p>

        <!-- Display the login error message if it exists -->
        <?php if (isset($_SESSION['login_error'])): ?>
            <p class="error"><?php echo $_SESSION['login_error']; ?></p>
            <?php unset($_SESSION['login_error']); // Clear error after displaying ?>
        <?php endif; ?>

        <form action="login.php" method="POST">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
        
        <!-- This is where you add the link to the signup page -->
        <p>Don’t have an account? <a href="signup.php">Sign up now</a></p>
    </div>
</body>
</html>

