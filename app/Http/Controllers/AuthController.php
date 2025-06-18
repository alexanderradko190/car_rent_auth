<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Http\Response;
use Laravel\Socialite\Facades\Socialite;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

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

            $role = match ($gitUser->getEmail()) {
                'admin@example.com' => 'admin',
                'manager@example.com' => 'manager',
                'dev7.radko@gmail.com' => 'manager',
                default => 'user',
            };

            $user = User::updateOrCreate(
                ['email' => $gitUser->getEmail()],
                [
                    'name' => $gitUser->getName() ?? $gitUser->getNickname(),
                    'password' => bcrypt(Str::random(16))
                ]
            );

            if (!$user->hasRole($role)) {
                $user->syncRoles([$role]);
            }

            $token = JWTAuth::fromUser($user);
            $expiresIn = JWTAuth::factory()->getTTL() * 60;

            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => $expiresIn,
                'role' => $role,
                'user' => $user->only(
                    ['id', 'name', 'email']
                ),
            ], Response::HTTP_OK);

        } catch (\Exception $e) {
            return response()->json([
                'error' => 'OAuth authentication failed',
                'message' => $e->getMessage()
            ], 401);
        }
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'User logged out'], Response::HTTP_OK);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Failed to invalidate token'], 500);
        }
    }
}
