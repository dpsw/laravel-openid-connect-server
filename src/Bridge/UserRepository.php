<?php

namespace Idaas\Passport\Bridge;

use Idaas\OpenID\Repositories\UserRepositoryInterface;
use Idaas\OpenID\Repositories\UserRepositoryTrait;
use Laravel\Passport\Bridge\User;
use Laravel\Passport\Bridge\UserRepository as LaravelUserRepository;
use League\OAuth2\Server\Entities\UserEntityInterface;
use RuntimeException;

class UserRepository extends LaravelUserRepository implements UserRepositoryInterface
{

    use UserRepositoryTrait;

    /**
     * Returns an associative array with attribute (claim) keys and values
     */
    public function getAttributes(UserEntityInterface $user, $claims, $scopes)
    {
        $model = $this->getUserModel();
        $attributes = [
            'sub' => $user->getIdentifier(),
        ];

        $userEntity = (new $model)->findForPassport($user->getIdentifier());

        if (method_exists($userEntity, 'getPublicAttributes')) {
            $attributes = array_merge_recursive(
                $attributes,
                $userEntity->getPublicAttributes(),
            );
        }

        return $attributes;
    }

    private function getUserModel()
    {
        $provider = config('auth.guards.api.provider');

        if (is_null($model = config('auth.providers.' . $provider . '.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }

        return $model;
    }

    public function getUserInfoAttributes(UserEntityInterface $user, $claims, $scopes)
    {
        return $this->getAttributes($user, $claims, $scopes);
    }

    public function getUserByIdentifier($identifier) : ?UserEntityInterface
    {
        $model = $this->getUserModel();

        if (method_exists($model, 'findForPassport')) {
            $user = (new $model)->findForPassport($identifier);
        } else {
            $user = (new $model)->where('email', $identifier)->first();
        }

        if (!$user) {
            return null;
        }

        return new User($user->getAuthIdentifier());
    }
}
