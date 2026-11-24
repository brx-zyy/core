<?php

use PHPUnit\Framework\TestCase;

/**
 * Security probe for the impact of unrestricted role assignment in the users addon.
 *
 * This test verifies that assigning an existing role through the same database
 * field used by users/pages/users.php immediately grants that role's permissions.
 * It is an impact test; the HTTP/backend authorization path is reviewed separately.
 *
 * @internal
 */
final class rex_user_role_assignment_security_test extends TestCase
{
    private int $userId;
    private int $roleId;
    private string $login;

    protected function setUp(): void
    {
        rex_user::setRoleClass(rex_user_role::class);

        $this->login = 'role_probe_' . bin2hex(random_bytes(5));

        $role = rex_sql::factory();
        $role->setTable(rex::getTablePrefix() . 'user_role');
        $role->setValue('name', 'Security probe role');
        $role->setValue('description', 'Temporary test role');
        $role->setValue('perms', json_encode([
            rex_perm::GENERAL => '|backup[export]|',
            rex_perm::OPTIONS => '',
            rex_perm::EXTRAS => '',
        ], JSON_THROW_ON_ERROR));
        $role->insert();
        $this->roleId = (int) $role->getLastId();

        $user = rex_sql::factory();
        $user->setTable(rex::getTablePrefix() . 'user');
        $user->setValue('name', 'Role assignment probe');
        $user->setValue('login', $this->login);
        $user->setValue('password', rex_login::passwordHash('Temporary-Test-Password-123!'));
        $user->setValue('status', 1);
        $user->setValue('login_tries', 0);
        $user->setValue('admin', 0);
        $user->setValue('role', '');
        $user->insert();
        $this->userId = (int) $user->getLastId();
    }

    protected function tearDown(): void
    {
        if (isset($this->userId)) {
            rex_user::clearInstance($this->userId);
            rex_sql::factory()->setQuery(
                'DELETE FROM ' . rex::getTablePrefix() . 'user WHERE id = ?',
                [$this->userId],
            );
        }

        if (isset($this->roleId)) {
            rex_sql::factory()->setQuery(
                'DELETE FROM ' . rex::getTablePrefix() . 'user_role WHERE id = ?',
                [$this->roleId],
            );
        }
    }

    public function testAssigningAnExistingRoleGrantsItsPermissionsWithoutGrantingAdmin(): void
    {
        $user = rex_user::require($this->userId);

        self::assertFalse($user->isAdmin());
        self::assertFalse($user->hasPerm('backup[export]'));

        // This is the exact role-field assignment performed by the users page handler.
        $submittedRoleIds = [(string) $this->roleId];
        $update = rex_sql::factory();
        $update->setTable(rex::getTablePrefix() . 'user');
        $update->setWhere(['id' => $this->userId]);
        $update->setValue('role', implode(',', $submittedRoleIds));
        $update->update();

        rex_user::clearInstance($this->userId);
        $updatedUser = rex_user::require($this->userId);

        self::assertFalse($updatedUser->isAdmin(), 'Role assignment must not implicitly set the admin flag.');
        self::assertTrue(
            $updatedUser->hasPerm('backup[export]'),
            'The assigned role grants backup export permission to the previously restricted account.',
        );
    }
}
