<?php

namespace Apollo16\Core\Auth\Role;

/**
 * Role Authorization.
 *
 * @author      mohammad.anang  <m.anangnur@gmail.com>
 */

trait AuthorizableRole
{
    /**
     * List of abilities that this role had.
     *
     * @return array
     */
    public function permissions()
    {
        return (property_exists($this, 'permissible'))
            ? $this->{$this->permissible}
            : $this->permissions;
    }

    /**
     * Role identifier.
     *
     * @return string
     */
    public function identifier()
    {
        return (property_exists($this, 'identifier'))
            ? $this->{$this->identifier}
            : $this->id;
    }
}