<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            // Validate dữ liệu đầu vào
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email|max:255',
                'password' => 'required|string',
            ], [
                'email.required' => 'Email là bắt buộc.',
                'email.string' => 'Email phải là chuỗi.',
                'email.email' => 'Email phải là một địa chỉ email hợp lệ.',
                'email.max' => 'Email không được quá 255 ký tự.',

                'password.required' => 'Mật khẩu là bắt buộc.',
                'password.string' => 'Mật khẩu phải là chuỗi.',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'errors' => $validator->errors()
                ], 422);
            }

            // Kiểm tra thông tin người dùng
            $user = User::where('email', $request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json(['message' => 'Unauthenticated.'], 401);
            }

            // Tạo token
            $tokenResult = $user->createToken('authToken')->plainTextToken;


            return response()->json([
                'status_code' => 200,
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'data' => $user
            ]);
        } catch (\Exception $error) {
            return response()->json([
                'status_code' => 500,
                'message' => 'Error in Login',
                'error' => $error,
            ]);
        }
    }
    public function register(Request $request)
    {
        try {
            // Kiểm tra và validate dữ liệu
            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => ['required', Password::min(8)],
            ], [
                'name.required' => 'Tên là bắt buộc.',
                'name.string' => 'Tên phải là chuỗi.',
                'name.max' => 'Tên không được quá 255 ký tự.',

                'email.required' => 'Email là bắt buộc.',
                'email.string' => 'Email phải là chuỗi.',
                'email.email' => 'Email phải là một địa chỉ email hợp lệ.',
                'email.max' => 'Email không được quá 255 ký tự.',
                'email.unique' => 'Email đã được sử dụng.',

                'password.required' => 'Mật khẩu là bắt buộc.',
                'password.min' => 'Mật khẩu phải có ít nhất 8 ký tự.',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'errors' => $validator->errors()
                ], 422);  // Đảm bảo trả về mã lỗi 422 và thông báo lỗi
            }

            // Tạo người dùng mới
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            return response()->json(['data' => $user], 200);
        } catch (\Exception $error) {
            return response()->json([
                'status_code' => 500,
                'message' => 'Error in register',
                'error' => $error,
            ]);
        }
    }

    /**
     * Đăng xuất người dùng.
     */
    public function logout(Request $request)
    {
        // Xóa token của người dùng
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out successfully'], 200);
    }
}
