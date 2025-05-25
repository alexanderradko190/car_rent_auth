<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Facades\JWTAuth;
use Exception;

class JwtMiddleware
{
    public function handle($request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            $request->merge(['user' => $user]);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'Invalid or expired token',
                'message' => $e->getMessage()
            ], 401);
        }

        return $next($request);
    }
}
