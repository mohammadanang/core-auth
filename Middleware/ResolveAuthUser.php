<?php

namespace Apollo16\Core\Auth\Middleware;

use Closure;
use Illuminate\Auth\Guard;
use Illuminate\Config\Repository;

/**
 * Resolve authenticated user middleware.
 *
 * @author      mohammad.anang  <m.anangnur@gmail.com>
 */

class ResolveAuthUser
{
    /**
     * Auth Guard instance.
     *
     * @var \Illuminate\Auth\Guard
     */
    protected $auth;

    /**
     * Create new middleware instance.
     *
     * @param \Illuminate\Auth\Guard        $auth
     * @param \Illuminate\Config\Repository $config
     */
    public function __construct(Guard $auth, Repository $config)
    {
        $this->auth = $auth;
        $this->config = $config;
    }

    /**
     * Handle incoming request.
     *
     * @param \Illuminate\Http\Request  $request
     * @param \Closure                  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        // check if this an auth.shield instance
        if ($this->config->get('auth.driver') === 'apollo16.shield') {
            $this->auth->user();
        }

        return $next($request);
    }
}