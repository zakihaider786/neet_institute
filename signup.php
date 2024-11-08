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
    // Check if all required fields are set
    if (isset($_POST['username'], $_POST['name'], $_POST['email'], $_POST['password'], $_POST['department'])) {
        $username = $_POST['username'];
        $name = $_POST['name'];  
        $email = $_POST['email'];
        $password = $_POST['password'];
        $department = $_POST['department'];

        // Check if any of the fields are empty
        if (empty($username) || empty($name) || empty($email) || empty($password) || empty($department)) {
            $_SESSION['signup_error'] = "All fields are required!";
        } else {
            // Check if email already exists
            $checkEmailQuery = "SELECT * FROM users WHERE email = ?";
            if ($stmt = $conn->prepare($checkEmailQuery)) {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $stmt->store_result();
                
                if ($stmt->num_rows > 0) {
                    // Email already exists
                    $_SESSION['signup_error'] = "The email address is already registered. Please use a different email.";
                } else {
                    // Hash the password before saving it
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                    // SQL query to insert user data
                    $sql = "INSERT INTO users (username, name, email, password, department) VALUES (?, ?, ?, ?, ?)";
                    if ($stmt = $conn->prepare($sql)) {
                        $stmt->bind_param("sssss", $username, $name, $email, $hashed_password, $department); // Bind the parameters
                        if ($stmt->execute()) {
                            // Successful signup
                            $_SESSION['signup_success'] = "Account created successfully! You can log in now.";
                            header("Location: login.php"); // Redirect to login page after successful signup
                            exit();
                        } else {
                            // Error inserting user
                            $_SESSION['signup_error'] = "An error occurred while creating your account. Please try again later.";
                        }
                    } else {
                        // Error in preparing SQL statement
                        $_SESSION['signup_error'] = "An error occurred. Please try again later.";
                    }
                }
                $stmt->close();
            } else {
                // Error checking email
                $_SESSION['signup_error'] = "An error occurred. Please try again later.";
            }
        }
    } else {
        $_SESSION['signup_error'] = "Please fill all the fields!";
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - NEET Institute</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="form-container">
        <h2>Create Account</h2>
        <p>Sign up to get started with your NEET Institute account.</p>

        <!-- Display the signup error message if it exists -->
        <?php if (isset($_SESSION['signup_error'])): ?>
            <p class="error"><?php echo $_SESSION['signup_error']; ?></p>
            <?php unset($_SESSION['signup_error']); // Clear error after displaying ?>
        <?php endif; ?>

        <!-- Display the signup success message if it exists -->
        <?php if (isset($_SESSION['signup_success'])): ?>
            <p class="success"><?php echo $_SESSION['signup_success']; ?></p>
            <?php unset($_SESSION['signup_success']); // Clear success message after displaying ?>
        <?php endif; ?>

        <form action="signup.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="text" name="name" placeholder="Full Name" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <select name="department" required>
                <option value="CCC">CCC</option>
                <option value="ADCA">ADCA</option>
                <option value="Typing">Typing</option>
                <option value="O Level">O Level</option>
                <option value="Python">Python</option>
            </select>
            <button type="submit">Sign Up</button>
        </form>

        <p>Already have an account? <a href="login.php">Log in now</a></p>
    </div>
</body>
</html>
