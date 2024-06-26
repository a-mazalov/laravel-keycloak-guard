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
     * @param string $tabn - Cоздать токен с заданым табельным.
     *  Eсли не указано сгенерирует случайные 6 цифр
     * @return void
     */
    public function initToken(?string $tabn = null)
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

        $this->payload = $this->makeFakePayload($tabn);

        $this->token = JWT::encode($this->payload, $this->privateKey, 'RS256');
    }

    /**
     * Форматирование открытого ключа для конфигурации laravel
     *
     * @param string|array $key
     * @return void
     */
    protected function plainPublicKey($key)
    {
      $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
      $string = trim(str_replace('-----END PUBLIC KEY-----', '', $string));
      $string = str_replace('\n', '', $string);
  
      return $string;
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

    /**
     * Сгенерировать данные в токене
     *
     * @return array
     */
    public function makeFakePayload(?string $tabn): array {
        $faker = Faker\Factory::create();

        $firstName = $faker->firstName();
        $lastName = $faker->lastName();
        $patronymicName = $faker->lastName();
        $tabnNumber = $tabn ?? $faker->numerify('######');

        return [
            "name" => "${firstName} ${lastName}",
            "fullName" => "${firstName} ${lastName} ${patronymicName}",
            "position" => "инженер-программист",
            "given_name" => $firstName,
            "family_name" => $lastName,
            "username" => $tabnNumber,
            'preferred_username' => $tabnNumber,
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