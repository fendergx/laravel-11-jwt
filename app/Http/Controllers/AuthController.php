<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use Illuminate\Http\Request;

class AuthController extends Controller
{

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'No autorizado'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me(Request $request)
    {
        // Validar el token usando la función validateToken
        //$validationResponse = $this->validateToken($request);
    
        // Si la validación devuelve un error (JsonResponse), lo retornamos
        /*if ($validationResponse instanceof \Illuminate\Http\JsonResponse) {
            return $validationResponse; // Devolver el error si ocurre
        }*/
    
        // Si el token es válido, retornar la información del usuario
        return response()->json(auth()->user());
    }
    
    protected function validateToken(Request $request)
{
    // Extraer el token desde el request
    $token = $request->input('token') ?? $request->bearerToken();

    // Validar si el token está presente
    if (!$token) {
        return response()->json([
            'error' => 'Token not provided',
            'code' => 400
        ], 400);
    }

    try {
        // Establecer el token y autenticar al usuario
        JWTAuth::setToken($token);
        $user = JWTAuth::authenticate();

        if (!$user) {
            return response()->json([
                'error' => 'User not found',
                'code' => 8000
            ], 404);
        }

        return $user; // Devolver el usuario si todo está bien

    } catch (TokenExpiredException $e) {
        return response()->json(['error' => 'Token expired', 'code' => 401], 401);
    } catch (TokenInvalidException $e) {
        return response()->json(['error' => 'Invalid token', 'code' => 401], 401);
    } catch (JWTException $e) {
        return response()->json(['error' => 'Token error', 'code' => 500], 500);
    }
}

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

    /**
     * Verificar el tiempo restante del token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkTokenExpiry(Request $request)
    {
        $request->validate([
            'token' => 'required|string',
        ]);
    
        try {
            // Obtener el token desde el cuerpo de la solicitud
            $token = $request->input('token');
            // Obtener los datos del token
            $payload = JWTAuth::setToken($token)->getPayload();
            // Calcular el tiempo restante
            $exp = $payload->get('exp');
            $remainingTime = $exp - now()->timestamp;
    
            return response()->json([
                'tiempo_restante_segundos' => $remainingTime,
            ]);
    
        } catch (TokenExpiredException $e) {
            return response()->json(['error' => 'Token expirado'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'No se pudo verificar el token'], 400);
        }
    }
    
}