<?php

use PHPUnit\Framework\TestCase;

/**
 * Security probe for role assignment through the users addon page handler.
 *
 * @internal
 */
final class rex_user_role_assignment_security_test extends TestCase
{
    private int $managerId;
    private int $managerRoleId;
    private int $privilegedRoleId;
    private ?rex_user $previousUser;
    private ?rex_backend_login $previousLogin;
    /** @var array<string, mixed> */
    private array $previousGet;
    /** @var array<string, mixed> */
    private array $previousPost;
    /** @var array<string, mixed> */
    private array $previousRequest;
    private ?\Symfony\Component\HttpFoundation\Request $previousHttpRequest;

    protected function setUp(): void
    {
        $this->previousUser = rex::getUser();
        $this->previousLogin = rex::getProperty('login');
        $this->previousGet = $_GET;
        $this->previousPost = $_POST;
        $this->previousRequest = $_REQUEST;
        $this->previousHttpRequest = rex::getProperty('request');

        rex_user::setRoleClass(rex_user_role::class);

        $this->managerRoleId = $this->createRole('Role assignment manager', '|users[]|');
        $this->privilegedRoleId = $this->createRole('Role assignment target', '|backup[export]|');
        $this->managerId = $this->createUser('role_manager_' . bin2hex(random_bytes(5)), (string) $this->managerRoleId);
    }

    protected function tearDown(): void
    {
        if (isset($this->managerId)) {
            rex_user::clearInstance($this->managerId);
            rex_sql::factory()->setQuery(
                'DELETE FROM ' . rex::getTablePrefix() . 'user WHERE id = ?',
                [$this->managerId],
            );
        }

        foreach ([$this->managerRoleId ?? null, $this->privilegedRoleId ?? null] as $roleId) {
            if (null !== $roleId) {
                rex_sql::factory()->setQuery(
                    'DELETE FROM ' . rex::getTablePrefix() . 'user_role WHERE id = ?',
                    [$roleId],
                );
            }
        }

        if (null !== $this->previousHttpRequest) {
            rex::setProperty('request', $this->previousHttpRequest);
        } else {
            rex::removeProperty('request');
        }

        if (isset($this->previousLogin)) {
            rex::setProperty('login', $this->previousLogin);
        } else {
            rex::removeProperty('login');
        }

        if (isset($this->previousUser)) {
            rex::setProperty('user', $this->previousUser);
        } else {
            rex::removeProperty('user');
        }

        if (isset($this->previousGet)) {
            $_GET = $this->previousGet;
            $_POST = $this->previousPost;
            $_REQUEST = $this->previousRequest;
        }
    }

    public function testNonAdminUserManagerCanAssignExistingPrivilegedRoleThroughUsersPageHandler(): void
    {
        $manager = rex_user::require($this->managerId);

        self::assertFalse($manager->isAdmin());
        self::assertTrue($manager->hasPerm('users[]'));
        self::assertFalse($manager->hasPerm('backup[export]'));

        rex::setProperty('user', $manager);
        // The backend page handler reads the active backend login object (e.g. passkey state).
        rex::setProperty('login', new rex_backend_login());

        $_GET = [];
        $_POST = [
            'user_id' => (string) $this->managerId,
            'FUNC_APPLY' => '1',
            'save' => '1',
            'userrole' => [(string) $this->privilegedRoleId],
            'userstatus' => '1',
            'useradmin' => '0',
            'userperm_be_sprache' => '',
            'userperm_startpage' => '',
            'username' => 'Role assignment manager',
            'userdesc' => '',
            'useremail' => '',
            'password_change_required' => '0',
        ];
        $_REQUEST = $_POST;
        rex::setProperty('request', \Symfony\Component\HttpFoundation\Request::create('http://localhost/redaxo/index.php', 'POST', $_POST));
        $token = rex_csrf_token::factory('user_edit')->getValue();
        $_POST[rex_csrf_token::PARAM] = $token;
        $_REQUEST[rex_csrf_token::PARAM] = $token;

        self::assertTrue(
            rex_csrf_token::factory('user_edit')->isValid(),
            'The simulated request must carry a valid REDAXO user-edit CSRF token.',
        );

        ob_start();
        try {
            require dirname(__DIR__) . '/pages/users.php';
        } finally {
            ob_end_clean();
        }

        rex_user::clearInstance($this->managerId);
        $updatedManager = rex_user::require($this->managerId);

        self::assertFalse($updatedManager->isAdmin(), 'The role assignment must not set the admin flag.');
        self::assertTrue(
            $updatedManager->hasPerm('backup[export]'),
            'The non-admin user manager gained a permission from an existing role through the real users page handler.',
        );
    }

    private function createRole(string $name, string $generalPermissions): int
    {
        $role = rex_sql::factory();
        $role->setTable(rex::getTablePrefix() . 'user_role');
        $role->setValue('name', $name);
        $role->setValue('description', 'Temporary security test role');
        $role->setValue('perms', json_encode([
            rex_perm::GENERAL => $generalPermissions,
            rex_perm::OPTIONS => '',
            rex_perm::EXTRAS => '',
        ], JSON_THROW_ON_ERROR));
        $role->addGlobalCreateFields();
        $role->addGlobalUpdateFields();
        $role->insert();

        return (int) $role->getLastId();
    }

    private function createUser(string $login, string $role): int
    {
        $user = rex_sql::factory();
        $user->setTable(rex::getTablePrefix() . 'user');
        $user->setValue('name', 'Role assignment manager');
        $user->setValue('login', $login);
        $user->setValue('password', rex_login::passwordHash('Temporary-Test-Password-123!'));
        $user->setValue('status', 1);
        $user->setValue('login_tries', 0);
        $user->setValue('admin', 0);
        $user->setValue('role', $role);
        $user->setDateTimeValue('lastlogin', time());
        $user->addGlobalCreateFields();
        $user->addGlobalUpdateFields();
        $user->insert();

        return (int) $user->getLastId();
    }
}
