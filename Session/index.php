<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

if (isset($_SESSION['user_id'])) {
    header('Location: home.php');
    exit;
}

$mode = ($_GET['mode'] ?? 'login') === 'register' ? 'register' : 'login';
$error = '';
$success = isset($_GET['registered']) ? 'Your account is ready. Sign in to continue.' : '';
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $mode = ($_POST['action'] ?? '') === 'register' ? 'register' : 'login';
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $csrfToken = (string) ($_POST['csrf_token'] ?? '');

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $error = 'Your session expired. Please try again.';
    } elseif ($mode === 'register') {
        $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

        if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $username)) {
            $error = 'Choose a username with 3–32 letters, numbers, or underscores.';
        } elseif (strlen($password) < 8 || strlen($password) > 12) {
            $error = 'Your password must be between 8 and 12 characters.';
        } elseif ($password !== $confirmPassword) {
            $error = 'Those passwords don’t match. Try again.';
        } else {
            try {
                $statement = $database->prepare(
                    'INSERT INTO users (username, password_hash) VALUES (:username, :password_hash)'
                );
                $statement->execute([
                    ':username' => $username,
                    ':password_hash' => password_hash($password, PASSWORD_DEFAULT),
                ]);

                header('Location: index.php?registered=1');
                exit;
            } catch (PDOException $exception) {
                if ($exception->getCode() === '23000') {
                    $error = 'That username is already taken. Try another one.';
                } else {
                    error_log('Account registration failed: ' . $exception->getMessage());
                    http_response_code(500);
                    $error = 'We couldn’t create your account right now. Please try again.';
                }
            }
        }
    } elseif ($username === '' || $password === '') {
        $error = 'Enter your username and password to continue.';
    } else {
        $statement = $database->prepare(
            'SELECT id, username, password_hash FROM users WHERE username = :username COLLATE NOCASE'
        );
        $statement->execute([':username' => $username]);
        $user = $statement->fetch();

        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int) $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            header('Location: home.php');
            exit;
        }

        $error = 'That username and password don’t match.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#246fb2">
    <title><?= $mode === 'register' ? 'Create your account' : 'Welcome back' ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body class="auth-page">
    <main class="auth-layout">
        <section class="auth-card" aria-labelledby="page-title">
            <?php if ($mode === 'register'): ?>
                <a class="brand auth-brand" href="index.php" aria-label="Daylight home">
                    <span class="brand-mark" aria-hidden="true">d</span>
                    <span>daylight</span>
                </a>
            <?php endif; ?>

            <div class="auth-copy">
                <?php if ($mode === 'register'): ?>
                    <p class="eyebrow">A fresh start</p>
                <?php endif; ?>
                <h1 id="page-title"><?= $mode === 'register' ? 'Create your account' : 'Good to see you again.' ?></h1>
                <p class="muted"><?= $mode === 'register' ? 'Choose a username and password to get started.' : 'Sign in and pick up right where you left off.' ?></p>
            </div>

            <?php if ($error !== ''): ?>
                <p class="notice notice-error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
            <?php elseif ($success !== ''): ?>
                <p class="notice notice-success" role="status"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></p>
            <?php endif; ?>

            <form class="auth-form" method="post" action="index.php<?= $mode === 'register' ? '?mode=register' : '' ?>">
                <input type="hidden" name="action" value="<?= $mode ?>">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

                <label for="username">Username</label>
                <input
                    id="username"
                    name="username"
                    type="text"
                    placeholder="e.g. alex_morgan"
                    value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>"
                    minlength="3"
                    maxlength="32"
                    autocomplete="username"
                    <?= $mode === 'register' ? 'aria-describedby="username-help"' : '' ?>
                    required
                    autofocus
                >
                <?php if ($mode === 'register'): ?>
                    <p class="field-help" id="username-help">Use 3–32 letters, numbers, or underscores.</p>
                <?php endif; ?>

                <div class="label-row">
                    <label for="password">Password</label>
                    <?php if ($mode === 'login'): ?>
                        <span class="field-hint">At least 8 characters</span>
                    <?php endif; ?>
                </div>
                <input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Enter your password"
                    minlength="8"
                    maxlength="<?= $mode === 'register' ? '12' : '72' ?>"
                    autocomplete="<?= $mode === 'register' ? 'new-password' : 'current-password' ?>"
                    <?= $mode === 'register' ? 'aria-describedby="password-help"' : '' ?>
                    required
                >
                <?php if ($mode === 'register'): ?>
                    <p class="field-help" id="password-help">Choose 8–12 characters. Your password is stored securely.</p>
                <?php endif; ?>

                <?php if ($mode === 'register'): ?>
                    <label for="confirm_password">Confirm password</label>
                    <input
                        id="confirm_password"
                        name="confirm_password"
                        type="password"
                        placeholder="Enter your password again"
                        minlength="8"
                        maxlength="12"
                        autocomplete="new-password"
                        aria-describedby="confirm-password-help"
                        required
                    >
                    <p class="field-help" id="confirm-password-help">Enter the same password again.</p>
                <?php endif; ?>

                <button class="button button-primary button-full" type="submit">
                    <?= $mode === 'register' ? 'Create your account' : 'Sign in' ?>
                    <?php if ($mode === 'register'): ?>
                        <span aria-hidden="true">↗</span>
                    <?php endif; ?>
                </button>
            </form>

            <p class="auth-switch">
                <?= $mode === 'register' ? 'Already have an account?' : 'New around here?' ?>
                <a href="index.php<?= $mode === 'register' ? '' : '?mode=register' ?>">
                    <?= $mode === 'register' ? 'Sign in' : 'Create an account' ?>
                </a>
            </p>

        </section>

    </main>
</body>
</html>
