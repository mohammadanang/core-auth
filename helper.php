<?php

/**
 * Helper file for foundry authentication.
 *
 * @author      mohammad.anang  <m.anangnur@gmail.com>
 */
if (!function_exists('shield')) {

    /**
     * Resolve shield instance from the container.
     *
     * @return \Apollo16\Core\Auth\Shield
     */
    function shield()
    {
        return app('auth.drive');
    }

    /**
     * Determine if a user has access to a certain permission.
     *
     * @param string $permission
     * @return bool
     */
    function can($permission)
    {
        return shield()->can($permission);
    }

    /**
     * Determine if a user don't have any access to a certain permission.
     *
     * @param string $permission
     * @return bool
     */
    function cannot($permission)
    {
        return shield()->cannot($permission);
    }

    /**
     * Determine if a user has a specific roles.
     *
     * @param string $identifier
     * @return bool
     */
    function has_role($identifier)
    {
        return shield()->hasRole($identifier);
    }

    /**
     * Get all available permissions for this user.
     *
     * @return array
     */
    function permissions()
    {
        return shield()->permissions();
    }

    /**
     * Get list of roles for this user.
     *
     * @return array
     */
    function roles()
    {
        return shield()->roles();
    }
}