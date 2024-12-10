<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;

class RegisteredUserController extends Controller
{
    public function storePhoneNumber(Request $request)
    {
        $validator = Validator::make($request->phone, [
            'phone' => [
                'required',
                'numeric',
                'digits:11',
                'unique:' . User::class,
            ],
        ]);
        // Check if validation fails
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed.',
                'errors' => $validator->errors(),
            ], 422);
        }
        // Generate a 4-digit OTP
        $otp = str_pad(random_int(0, 9999), 4, '0', STR_PAD_LEFT);
        // Set OTP expiration time (current time + 120 seconds)
        $otpExpiresAt = now()->addSeconds(120);
        // Store the phone number and OTP in the database
        $user = User::create([
            'phone_number' => $request->phone,
            'otp_code' => $otp,
            'otp_timeout' => $otpExpiresAt,
            'otp_status' => 0,
        ]);
        // Send OTP via email
        $this->sendOtpEmail($user->phone, $otp);
        // Return success response
        return response()->json([
            'message' => 'Phone number and OTP saved successfully!',
            'data' => [
                'phone' => $user->phone,
                'otp_expires_at' => $otpExpiresAt,
            ],
        ], 201);

    }
        // Function to send OTP via email
            protected function sendOtpEmail($phone, $otp)
            {
                $staticEmail = 'mritilz2030@gmail.com';
                Mail::raw("Your OTP is: $otp", function ($message) use ($staticEmail, $phone) {
                    $message->to($staticEmail)
                            ->subject("OTP for Phone: $phone");
                });
            }
    //End First Step Phone Number and OTP
    public function store(Request $request): Response
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:'.User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->string('password')),
        ]);

        event(new Registered($user));

        Auth::login($user);

        return response()->noContent();
    }
}
