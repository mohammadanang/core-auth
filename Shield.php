<?php

namespace Apollo16\Core\Auth;

use Apollo16\Core\Contracts\Auth\Ownership;
use Apollo16\Core\Contracts\Auth\Permission\Permissible;
use Apollo16\Core\Contracts\Auth\Role\Authorizable as AuthorizableViaRole;
use Apollo16\Core\Contracts\Auth\Role\AuthorizableRole;
use Apollo16\Core\Contracts\Auth\Shield as ShieldContract;
use Illuminate\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;

/**
 * Shield implementation.
 *
 * @author      mohammad.anang  <m.anangnur@gmail.com>
 */

class Shield extends Guard implements ShieldContract
{
    /**
     * List of all assigned role for this user.
     *
     * @var array
     */
    protected $roles = [];

    /**
     * List of all resolved roles.
     *
     * @var array
     */
    protected $resolvedRoles = [];

    /**
     * Roles and permissions resolved indicator.
     *
     * @var bool
     */
    protected $resolved = false;

    /**
     * List of all combined permissions for this user.
     *
     * @var array
     */
    protected $permissions = [];

    /**
     * Attach role to list of roles.
     *
     * @param \Apollo16\Core\Contracts\Auth\Role\AuthorizableRole $role
     */
    public function attachRole(AuthorizableRole $role)
    {
        // if role is already registered on the list of roles we just need to resolve it
        if (array_key_exists($role->identifier(), $this->roles)) {
            $this->resolveRole($role);
        }

        $this->roles[$role->identifier()] = $role;

        $this->resolveRole($role);
    }

    /**
     * Resolve role.
     *
     * @param \Apollo16\Core\Contracts\Auth\Role\AuthorizableRole $role
     */
    public function resolveRole(AuthorizableRole $role)
    {
        if (!array_key_exists($role->identifier(), $this->resolvedRoles)) {
            foreach($role->permissions() as $permission) {
                $this->permissions[$permission][] = $role->identifier();
            }

            $this->resolvedRoles[$role->identifier()] = $role;
        }
    }

    /**
     * Get resolved roles.
     *
     * @param mixed $identifier
     * @return \Apollo16\Core\Contracts\Auth\Role\AuthorizableRole | null
     */
    public function getResolvedRole($identifier)
    {
        return (array_key_exists($identifier, $this->resolvedRoles))
            ? $this->resolvedRoles[$identifier]
            : null;
    }

    /**
     * Detach role from the list of roles.
     *
     * @param $identifier
     */
    public function detachRole($identifier)
    {
        $role = $this->getResolvedRole($identifier);

        if ($role instanceof AuthorizableRole) {
            foreach ($role->permissions() as $permission)
            {
                $this->removePermission($permission, $role);
            }

            unset($this->resolvedRoles[$identifier]);
        }
    }

    /**
     * Add permission to the list of permissions.
     *
     * @param $permission
     * @param $role
     */
    public function setPermission($permission, $role = null)
    {
        if (!array_key_exists($permission, $this->permissions)) {
            if ($role instanceof AuthorizableRole) {
                $this->permissions[$permission][] = $role->identifier();
            } else {
                $this->permissions[$permission][] = 'Auto';
            }
        }
    }

    /**
     * Remove permission from the list of permissions.
     *
     * @param $permission
     * @param null $role
     */
    public function removePermission($permission, $role = null)
    {
        if (array_key_exists($permission, $this->permissions) and empty($role)) {
            unset($this->permissions[$permission]);

            return;
        } elseif (array_key_exists($permission, $this->permissions)) {
            $_permission = $this->permissions[$permission];
            $_role = ($role instanceof AuthorizableRole) ? $role->identifier() : 'Auto';

            // determine role index
            $index = array_search($_role, $_permission);

            // if it an empty array, remove it entirely
            if (count($this->permissions[$permission]) < 1) {
                unset($this->permissions[$permission]);
            }
        }
    }

    /**
     * Determine if a user has a specific roles.
     *
     * @param string $identifier
     * @return bool
     */
    public function hasRole($identifier)
    {
        return array_key_exists($identifier, $this->resolvedRoles);
    }

    /**
     * Get list of roles for this user.
     *
     * @return array
     */
    public function roles()
    {
        return array_keys($this->resolvedRoles);
    }

    /**
     * Determine if a user has access to a certain permission.
     *
     * @param string|array $permission
     * @return bool
     */
    public function can($permission)
    {
        if ($this->isSuperUser()) {
            return true;
        }

        $_permission = (is_array($permission)) ? $permission : [$permission];

        return (count(array_intersect(array_keys($this->permissions), $_permission)) > 0);
    }

    /**
     * Determine if a user don't have any access to a certain permission.
     *
     * @param string $permission
     * @return bool
     */
    public function cannot($permission)
    {
        return !$this->can($permission);
    }

    /**
     * Determine if user si super user.
     *
     * @return bool
     */
    public function isSuperUser()
    {
        return array_key_exists('root', $this->permissions);
    }

    /**
     * Get all available permissions for this user.
     *
     * @return array
     */
    public function permissions()
    {
        return array_keys($this->permissions);
    }

    /**
     * Determine if this user is te ownership of certain resource.
     *
     * @param \Apollo16\Core\Contracts\Auth\Ownership $resource
     * @return bool
     */
    public function isOwner(Ownership $resource)
    {
        return ($this->user->getAuthIdentifier() == $resource->getOwnerIdentifier());
    }

    /**
     * Set the current user of the application.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     */
    public function setUser(UserContract $user)
    {
        parent::setUser($user);

        $this->resetRolesAndPermissions();
        $this->setRolesAndPermissions($user);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable | null
     */
    public function user()
    {
        $user = parent::user();

        if ($user instanceof UserContract and !$this->resolved) {
            $this->setRolesAndPermissions($user);
        }

        return $user;
    }

    /**
     * Set roles and permissions.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     */
    public function setRolesAndPermissions(UserContract $user)
    {
        if ($user instanceof Permissible) {
            foreach($user->permissions() as $permission)
            {
                $this->setPermission($permission);
            }
        }

        if ($user instanceof AuthorizableViaRole) {
            foreach($user->getRoles() as $role)
            {
                $this->attachRole($role);
            }
        }

        $this->resolved = true;
    }

    /**
     * Reset roles and permissions.
     */
    public function resetRolesAndPermissions()
    {
        $this->roles = [];
        $this->resolvedRoles = [];
        $this->permissions = [];
        $this->resolved = false;
    }

    /**
     * Remove the user data from the session and cookies.
     */
    protected function clearUserDataFromStorage()
    {
        parent::clearUserDataFromStorage();

        $this->resetRolesAndPermissions();
    }
}