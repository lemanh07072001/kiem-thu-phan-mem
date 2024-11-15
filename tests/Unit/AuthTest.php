<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Foundation\Testing\RefreshDatabase;

class AuthTest extends TestCase
{
    use RefreshDatabase;
    /**
     * Kiểm thử đăng ký thành công.
     * Kiểm tra phản hồi bao gồm thông tin người dùng và token khi đăng ký thành công.
     */
    public function test_register_successfully()
    {
        $response = $this->postJson('/api/register', data: [
            'name' => 'Test User',
            'email' => 'testuser@example.com',
            'password' => 'password',
        ]);


        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => ['id', 'name', 'email'],
            ]);


        $response->dump();

    }

    /**
     * Kiểm thử đăng ký thất bại với email đã tồn tại.
     * Kiểm tra phản hồi và thông báo lỗi khi email bị trùng lặp.
     */
    public function test_register_fails_due_to_duplicate_email()
    {
        User::factory()->create(['email' => 'testuser@example.com']);

        $response = $this->postJson('/api/register', data: [
            'name' => 'New User',
            'email' => 'testuser@example.com',
            'password' => Hash::make('password'),
        ]);
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);


        $response->dump();
    }

    /**
     * Kiểm thử đăng nhập thất bại khi không có email.
     */
    public function test_login_fails_with_missing_email()
    {
        $response = $this->postJson('/api/login', data: [
            'password' => 'password',
        ]);

        $response->assertStatus(status: 422)
            ->assertJsonValidationErrors(['email']);

        $response->dump();
    }

    /**
     * Kiểm thử đăng nhập thành công.
     * Đảm bảo rằng người dùng có thể đăng nhập thành công với token hợp lệ.
     */
    public function test_login_successfully()
    {
        $user = User::factory()->create();
        $token = $user->createToken('authToken')->plainTextToken;
        $response = $this->withHeaders(['Authorization' => "Bearer $token"])
        ->postJson('/api/login', data: [
            'email' => $user->email,
            'password' => 'password',
        ]);


        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => ['id', 'name', 'email'],
                'token' => 'access_token',
                'token_type' => 'token_type'
            ]);

        $response->dump();
    }

    /**
     * Kiểm thử thông tin cá nhân thất bại khi không có token.
     */
    public function test_profile_fails_without_token()
    {
        $response = $this->getJson('/api/user');

        $response->assertStatus(status: 401)
            ->assertJson(['message' => 'Unauthenticated.']);


        $response->dump();
    }

    /**
     * Kiểm thử thông tin cá nhân thành công khi có token
     */
    public function test_profile_successfully()
    {
        $user = User::factory()->create();
        $token = $user->createToken('authToken')->plainTextToken;

        $response = $this->withHeaders(['Authorization' => "Bearer $token"])->getJson('/api/user');


        $response->assertStatus(200)
            ->assertJsonStructure(['id', 'name', 'email']);

        $response->dump();
    }

    /**
     * Kiểm thử đăng xuất thành công.
     * Đảm bảo rằng người dùng có thể đăng xuất thành công với token hợp lệ.
     */
    public function test_logout_successfully()
    {
        $user = User::factory()->create();
        $token = $user->createToken('authToken')->plainTextToken;

        $response = $this->withHeaders(headers: ['Authorization' => "Bearer $token"])
        ->postJson('/api/logout');

        $response->assertStatus(200)
            ->assertJson(['message' => 'Logged out successfully']);


        $response->dump();
    }

    /**
     * Kiểm thử đăng xuất thất bại khi không có token.
     */
    public function test_logout_fails_without_token()
    {
        // Gửi yêu cầu đăng xuất mà không có token
    $response = $this->postJson('/api/logout');

    // Kiểm tra mã trạng thái và thông báo lỗi
    $response->assertStatus(401)
             ->assertJson(['message' => 'Unauthenticated.']);

        $response->dump();

    }
}
