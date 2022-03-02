<?php

namespace KeycloakGuard;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;

class KeycloakGuard implements Guard
{
	private $config;
	private $user;
	private $provider;
	private $decodedToken;

	public function __construct(UserProvider $provider, Request $request)
	{
		$this->config = config('keycloak');
		$this->user = null;
		$this->provider = $provider;
		$this->decodedToken = null;
		$this->request = $request;

		if($this->config['token_leeway']) {
			JWT::$leeway = $this->config['token_leeway'];
		}

		$this->authenticate();
	}

	/**
	 * Decode token, validate and authenticate user
	 *
	 * @return mixed
	 */

	private function authenticate()
	{
		try {
			$this->decodedToken = Token::decode($this->request->bearerToken(), $this->config['realm_public_key']);
		} catch (\Exception $e) {
			/*
			* В случае истекшего токена, обработать исключение и вернуть 401
			*/
			if ($e instanceof ExpiredException) {
				throw new AuthenticationException($e->getMessage());
			}

			throw new TokenException($e->getMessage());
		}

		if ($this->decodedToken) {
			$this->validate([
				$this->config['user_provider_credential'] => $this->decodedToken->{$this->config['token_principal_attribute']}
			]);
		}
	}


	/**
	 * Determine if the current user is authenticated.
	 *
	 * @return bool
	 */
	public function check()
	{
		return !is_null($this->user());
	}

	/**
	 * Determine if the guard has a user instance.
	 *
	 * @return bool
	 */
	public function hasUser()
	{
		return !is_null($this->user());
	}

	/**
	 * Determine if the current user is a guest.
	 *
	 * @return bool
	 */
	public function guest()
	{
		return !$this->check();
	}

	/**
	 * Get the currently authenticated user.
	 *
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function user()
	{
		if (is_null($this->user)) {
			return null;
		}

		if ($this->config['append_decoded_token']) {
			$this->user->token = $this->decodedToken;
		}

		return $this->user;
	}

	/**
	 * Get the ID for the currently authenticated user.
	 *
	 * @return int|null
	 */
	public function id()
	{
		if ($user = $this->user()) {
			return $this->user()->id;
		}
	}

	/**
	 * Validate a user's credentials.
	 *
	 * @param  array  $credentials
	 * @return bool
	 */
	public function validate(array $credentials = [])
	{
		if (!$this->decodedToken) {
			return false;
		}

		if ($this->config['check_resources']) {
			$this->validateResources();
		}

		if ($this->config['load_user_from_database']) {
			$user = $this->provider->retrieveByCredentials($credentials);
			$tabn = $credentials['tabn'] ?? null;

			if (!$user) {

				if (env('HR_USER_KGB') != $tabn) {
					Log::error("User not found. Credentials: " . json_encode($credentials));
				}

				// Eсли пользователя не найдено в базе, вернуть пустую модель
				$class = $this->provider->getModel();
				$user = new $class();
			}
		} else {
			$class = $this->provider->getModel();
			$user = new $class();
		}

		$this->setUser($user);

		return true;
	}

	/**
	 * Set the current user.
	 *
	 * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
	 * @return void
	 */
	public function setUser(Authenticatable $user)
	{
		$this->user = $user;
	}

	/**
	 * Validate if authenticated user has a valid resource
	 *
	 * @return void
	 */
	private function validateResources()
	{
		$token_resource_access = array_keys((array)($this->decodedToken->resource_access ?? []));
		$allowed_resources = explode(',', $this->config['allowed_resources']);

		if (count(array_intersect($token_resource_access, $allowed_resources)) == 0) {
			throw new ResourceAccessNotAllowedException("The decoded JWT token has not a valid `resource_access` allowed by API. Allowed resources by API: " . $this->config['allowed_resources']);
		}
	}

	/**
	 * Returns full decoded JWT token from athenticated user
	 *
	 * @return mixed|null
	 */
	public function token()
	{
		return json_encode($this->decodedToken);
	}

	/**
	 * Check if authenticated user has a especific role into resource
	 * @param string $resource
	 * @param string|array $role
	 * @param bool $strict - требуется точное совпадение ролей. Только для массивов
	 * @return bool
	 */
	public function hasRole($resource, $role, $strict = false)
	{
		$token_resource_access = (array)$this->decodedToken->resource_access;

		// Проверить наличие ресурса в токене
		if (!array_key_exists($resource, $token_resource_access)) {
			return false;
		}

		$token_resource_values = (array)$token_resource_access[$resource];

		if (array_key_exists('roles', $token_resource_values)) {

			if (is_array($role)) {

				$result = array_intersect($role, $token_resource_values['roles']);

				// В случае необходимости полного совпадения
				if ($strict) {
					return count($role) === count($result);
				}

				// Если есть совпадения
				return !empty(array_intersect($role, $token_resource_values['roles']));
			} else {
				// Если необходимо проверить одну роль
				return in_array($role, $token_resource_values['roles']);
			}
		}

		return true;
	}


	/**
	 * Проверка роли для ресурса указанного в .env файле.
	 * 
	 * @param string|array $role
	 * @return bool
	 */
	public function hasResourceRole($role)
	{
		$resourcesInConfig = config('keycloak')['allowed_resources'];

		// Если ресурсы заданы через запятую
		$resource_array = array_map('trim', explode(',', $resourcesInConfig));

		foreach ($resource_array as $resource) {
			return $this->hasRole($resource, $role, false);
		}
	}
}
