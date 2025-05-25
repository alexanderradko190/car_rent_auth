<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::prefix('auth')->group(function () {
    Route::get('github/redirect', [AuthController::class, 'redirectToGitHub']);
    Route::get('github/callback', [AuthController::class, 'handleGitHubCallback']);
});

Route::middleware('jwt.auth')->post('/auth/logout', [AuthController::class, 'logout']);

