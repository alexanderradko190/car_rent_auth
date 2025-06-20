<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;

class RolesSeeder extends Seeder
{
    public function run(): void
    {
        Role::firstOrCreate(['name' => 'user']);
        Role::firstOrCreate(['name' => 'manager']);
        Role::firstOrCreate(['name' => 'admin']);
    }
}
