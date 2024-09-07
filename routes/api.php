<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::get('/', function () {
    return view('welcome');
});

//Route::get('/user', [UserController::class, 'index']);

Route::group([
    
    'middleware' => 'api',
    'prefix' => 'v1'  

], function ($router) {

    Route::post('login', [AuthController::class,'login']);
    Route::post('logout', [AuthController::class,'logout']);
    Route::post('refresh', [AuthController::class,'refresh']);
    Route::post('me', [AuthController::class,'me']);
    Route::get('checktoken', [AuthController::class,'checkTokenExpiry']);
});
