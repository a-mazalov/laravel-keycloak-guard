<?php

namespace KeycloakGuard\Tests;

use Illuminate\Support\Facades\Auth;
use KeycloakGuard\ActingAsKeycloakUser;

class RoleTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    public function test_token_without_roles_key_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    // 'roles' => []
                ],
            ]
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret')
            ->assertOk();

        $this->assertFalse(Auth::hasRole('myapp-backend', ["ROLE_1"]));
    }
}
