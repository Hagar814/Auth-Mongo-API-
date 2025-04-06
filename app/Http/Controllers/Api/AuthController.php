<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Validation\Rules;
use App\Helpers\ApiResponse;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
class AuthController extends Controller
{
    public function register (Request $request)
    {
        $validator = Validator::make($request->all(),[
            'name'=>['required','string','max:255'],
            'email'=>['required','email','max:255','unique:'.User::class],
            'password'=>['required','confirmed',Rules\Password::defaults()],
            
            
            
        ]);

        if ($validator->fails())
        {
            return ApiResponse::sendResponse(422,'Register Validation Errors', $validator->messages()->all());
        }

        $user = User::create(

            [
                'name'=> $request->name,
                'email'=>$request->email,
                'password' => Hash::make($request->password)
            ]
        );

        //$data['token'] = $user->createToken('MongoAPI', ['*'])->plainTextToken;
        //$data['user'] = $user->name;
        //$data['email'] = $user->email;
        $token = $user->createToken('user-token')->plainTextToken;
    
        return ApiResponse::sendResponse(201,'User Account Created Successfully', $token);
    }
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(),[
            'email'=>['required','email','max:255'],
            'password'=>['required',],
            
            
        ]);
        if ($validator->fails())
        {
            return ApiResponse::sendResponse(422,'Login Validation Errors', $validator->errors());
        }
        if (Auth::guard('user')->attempt(['email' => $request->email, 'password' => $request->password])) {
            $currentUser = Auth::guard('user')->user();
            $token = $currentUser->createToken('user')->plainTextToken;
            return ApiResponse::sendResponse(200, 'Patient Logged In Successfully', ['token' => $token]);
        
        } else {
            // Return invalid credentials message
            return ApiResponse::sendResponse(401, 'Invalid credentials', null);
        }
    }

public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        
        return ApiResponse::sendResponse(200,'Admin Logged Out Successfully', []);
    
       
}
}
