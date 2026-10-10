<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

if (!isset($_SESSION['user_id'], $_SESSION['username'])) {
    header('Location: index.php');
    exit;
}

$firstName = htmlspecialchars(explode('_', (string) $_SESSION['username'])[0], ENT_QUOTES, 'UTF-8');
$username = htmlspecialchars((string) $_SESSION['username'], ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#eaf3fb">
    <title>Home</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body class="home-page">
    <header class="site-header">
        <div class="header-right">
            <form method="post" action="logout.php">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                <button class="signout-button" type="submit">Sign out</button>
            </form>
        </div>
    </header>

    <main class="home-main">
        <section class="welcome-section">
            <div class="welcome-copy">
                <h1>Welcome, <?= $firstName ?></h1>
                <p class="welcome-subtitle">You’re signed in as <strong><?= $username ?></strong>. Your account is ready.</p>
            </div>
        </section>
    </main>
</body>
</html>
