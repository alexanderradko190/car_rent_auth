<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Tymon\JWTAuth\Facades\JWTAuth;
use Exception;

class AuthController extends Controller
{
    public function redirectToGitHub()
    {
        return Socialite::driver('github')
            ->stateless()
            ->redirect();
    }

    public function handleGitHubCallback()
    {
        try {
            $gitUser = Socialite::driver('github')->stateless()->user();
            
            if (!$gitUser->getEmail()) {
                return response()->json([
                    'error' => 'Email required',
                    'message' => 'GitHub account must have public email'
                ], 400);
            }

            $user = User::updateOrCreate(
                ['email' => $gitUser->getEmail()],
                [
                    'name' => $gitUser->getName() ?? $gitUser->getNickname(),
                    'password' => bcrypt(Str::random(16)),
                    'provider_id' => $gitUser->getId(),
                    'provider_name' => 'github'
                ]
            );

            $token = JWTAuth::fromUser($user);

            return response()->json([
                'token' => $token,
                'user' => $user->makeHidden(['password', 'provider_id'])
            ]);

        } catch (Exception $e) {
            return response()->json([
                'error' => 'Не удалось авторизоваться',
                'message' => $e->getMessage()],
                401,
                [],
                JSON_UNESCAPED_UNICODE
        );
        }
    }

    public function logout(Request $request)
    {
        try {
            if (!JWTAuth::check()) {
                return response()->json(['error' => 'Пользователь не авторизован'], 401);
            }

            JWTAuth::parseToken()->invalidate();

            return response()->json([
                'message' => 'Вы успешно вышли из системы', 
                'expired_at' => now()->toDateTimeString()],
                200,
                [],
                JSON_UNESCAPED_UNICODE
            );

        } catch (Exception $e) {
            return response()->json([
                'error' => 'Не удалось выйти из системы',
                'message' => $e->getMessage()],
            500,
            [],
            JSON_UNESCAPED_UNICODE
        );
        }
    }
}