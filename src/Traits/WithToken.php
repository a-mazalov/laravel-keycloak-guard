<?php

namespace KeycloakGuard\Traits;

use Firebase\JWT\JWT;
use Faker;

trait WithToken
{
    protected $token;
    protected $publicKey;
    protected $payload;
    protected $privateKey;

    /**
     * Сгенерировать токен
     *
     * @return void
     */
    public function initToken()
    {
        $this->privateKey = openssl_pkey_new(array(
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ));

        $this->publicKey = openssl_pkey_get_details($this->privateKey)['key'];

        config(['keycloak.realm_public_key' => $this->plainPublicKey($this->publicKey)]);
        config(['keycloak.token_principal_attribute' => 'preferred_username']);
        config(['keycloak.append_decoded_token' => true]);

        $this->payload = $this->makeFakePayload();

        $this->token = JWT::encode($this->payload, $this->privateKey, 'RS256');
    }

    /**
     * Добавить данные в токен
     *
     * @param array $payload
     * @return void
     */
    protected function buildCustomToken(array $payload)
    {
        $payload = array_replace($this->payload, $payload);

        $this->token = JWT::encode($payload, $this->privateKey, 'RS256');
    }

    /**
     * Добавить роль в ресурс
     *
     * @param string $resource
     * @param array $roles
     * @return void
     */
    protected function addResourceRolesToken(string $resource, array $roles)
    {
        $access['resource_access'][$resource]['roles'] = $roles;

        $this->buildCustomToken($access);
    }

    public function makeFakePayload(): array {
        $faker = Faker\Factory::create();

        $firstName = $faker->firstName();
        $lastName = $faker->lastName();
        $patronymicName = $faker->lastName();
        $tabn = $faker->numerify('######');

        return [
            "name" => "${firstName} ${lastName}",
            "fullName" => "${firstName} ${lastName} ${patronymicName}",
            "position" => "инженер-программист",
            "given_name" => $firstName,
            "family_name" => $lastName,
            "username" => $tabn,
            'preferred_username' => $tabn,
            'resource_access' => [
                'test_client' => [
                    "roles" => [
                        "test_role",
                    ]
                ]
            ]
        ];
    }
}
