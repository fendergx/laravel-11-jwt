<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class PrimerUsuarioSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $contraseña = "123";
        $user = new User([
            "email" => "admin@gmail.com",
            "password" => Hash::make($contraseña),
            "name" => "Administrador",
        ]);
        $user->saveOrFail();
    }
}
