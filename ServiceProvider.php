<?php

namespace Apollo16\Core\Auth;

use Apollo16\Core\Contracts\Auth\Shield as ShieldContract;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Support\ServiceProvider as LaravelServiceProvider;

/**
 * Auth Shield Service Provider.
 *
 * @author      mohammad.anang  <m.anangnur@gmail.com>
 */

class ServiceProvider extends LaravelServiceProvider
{
    /**
     * Register the service provider.
     */
    public function register()
    {
        $this->app['auth']->extend('apollo16.shield', function ($app) {
            $shield = new Shield(
                new EloquentUserProvider($app['hash'], $app['config']->get('auth.model')),
                $app['session.store']
            );

            $shield->setCookieJar($app['cookie']);
            $shield->setDispatcher($app['events']);
            $shield->setRequest($app->refresh('request', $shield, 'setRequest'));

            return $shield;
        });

        // share and register shield's auth to the application container
        // only if the default driver is set to shield.
        if ($this->app['config']['auth.driver'] == 'apollo16.shield') {
            $this->app->alias('auth.driver', Shield::class);
            $this->app->alias('auth.driver', ShieldContract::class);

            // and a helper file to make your life easier :)
            require __DIR__.'/helper.php';
        }
    }
}