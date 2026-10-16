<?php

namespace Maklad\Permission;

use Illuminate\Contracts\Auth\Access\Authorizable;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Collection;
use Maklad\Permission\Contracts\PermissionInterface as Permission;
use MongoDB\BSON\Document;

/**
 * Class PermissionRegistrar
 * @package Maklad\Permission
 */
class PermissionRegistrar
{
    protected Gate $gate;

    protected Repository $cache;

    protected string $cacheKey = 'maklad.permission.cache';

    protected string $permissionClass;

    protected string $roleClass;

    /**
     * PermissionRegistrar constructor.
     * @param Gate $gate
     * @param Repository $cache
     */
    public function __construct(Gate $gate, Repository $cache)
    {
        $this->gate = $gate;
        $this->cache = $cache;
        $this->permissionClass = config('permission.models.permission');
        $this->roleClass = config('permission.models.role');
    }

    /**
     * Register Permissions
     *
     * @return bool
     */
    public function registerPermissions(): bool
    {
        $this->getPermissions()->map(function (Permission $permission) {
            $this->gate->define($permission->name, function (Authorizable $user) use ($permission) {
                return $user->hasPermissionTo($permission) ?: null;
            });
        });

        return true;
    }

    /**
     * Forget cached permission
     */
    public function forgetCachedPermissions(): void
    {
        $this->cache->forget($this->cacheKey);
    }

    /**
     * Get Permissions
     *
     * The permissions are cached as Extended JSON strings rather than serialized models, so they can be read back
     * when the cache does not unserialize objects (cache.serializable_classes) and keep their exact BSON types.
     *
     * @return Collection
     */
    public function getPermissions(): Collection
    {
        $documents = $this->cache->remember($this->cacheKey, config('permission.cache_expiration_time'), function () {
            return $this->getPermissionClass()->get()->map(function ($permission) {
                return Document::fromPHP($permission->getAttributes())->toCanonicalExtendedJSON();
            })->all();
        });

        // Older releases cached the models themselves, which may come back as incomplete objects
        if (! is_array($documents)) {
            $this->forgetCachedPermissions();

            return $this->getPermissions();
        }

        return $this->getPermissionClass()->hydrate(array_map(function (string $document) {
            return Document::fromJSON($document)->toPHP(['root' => 'array', 'document' => 'array', 'array' => 'array']);
        }, $documents));
    }

    /**
     * Get Permission class
     *
     * @return Application|mixed
     */
    public function getPermissionClass(): mixed
    {
        return app($this->permissionClass);
    }

    /**
     * Get Role class
     *
     * @return Application|mixed
     */
    public function getRoleClass(): mixed
    {
        return app($this->roleClass);
    }
}
