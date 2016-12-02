<?php

namespace QuanNH\DigitalSignature;

use Illuminate\Support\ServiceProvider;

class DigitalSignatureServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/config' => config_path(),
        ]);
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/config/signature.php', 'digital-signature'
        );

        $this->app->singleton('digitalsignature', function () {
            return new DigitalSignature;
        });
    }
}
