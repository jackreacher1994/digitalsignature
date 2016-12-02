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
        //
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('digitalsignature', function () {
            return new DigitalSignature;
        });
    }
}
