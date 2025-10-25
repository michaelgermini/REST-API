# API avec PHP et Laravel

## Introduction

**Laravel** est le framework PHP le plus populaire pour le développement web et les APIs. Il offre une **syntaxe élégante**, un **écosystème** riche et des outils puissants pour créer des APIs REST robustes. Laravel suit les principes du **SOLID** et intègre de nombreuses fonctionnalités modernes comme l'authentification, l'autorisation, et la validation. Dans ce chapitre, nous allons créer une API REST complète avec Laravel.

## Configuration du projet

### Installation

```bash
# Installation de Laravel via Composer
composer create-project laravel/laravel blog-api
cd blog-api

# Installation des dépendances
composer install

# Configuration de l'environnement
cp .env.example .env
php artisan key:generate
```

### Installation des packages

```bash
# API et authentification
composer require laravel/sanctum
composer require tymon/jwt-auth

# Base de données et migrations
composer require doctrine/dbal

# Validation et sécurité
composer require spatie/laravel-permission

# Documentation
composer require --dev l5-swagger

# Tests
composer require --dev phpunit/phpunit
```

### Structure du projet

```
blog-api/
├── app/
│   ├── Http/
│   │   ├── Controllers/
│   │   │   ├── Auth/
│   │   │   │   ├── LoginController.php
│   │   │   │   └── RegisterController.php
│   │   │   ├── UserController.php
│   │   └── PostController.php
│   │   ├── Middleware/
│   │   │   ├── Authenticate.php
│   │   │   └── CorsMiddleware.php
│   │   └── Requests/
│   │       ├── StoreUserRequest.php
│   │       └── UpdateUserRequest.php
│   ├── Models/
│   │   ├── User.php
│   │   └── Post.php
│   └── Providers/
├── config/
├── database/
│   ├── migrations/
│   └── seeders/
├── routes/
│   ├── api.php
│   └── web.php
├── tests/
│   ├── Feature/
│   └── Unit/
├── composer.json
└── artisan
```

### Configuration

```php
// .env
APP_NAME="Blog API"
APP_ENV=local
APP_KEY=base64:your-app-key-here
APP_DEBUG=true
APP_URL=http://localhost:8000

LOG_CHANNEL=stack
LOG_LEVEL=debug

DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=blogdb
DB_USERNAME=user
DB_PASSWORD=password

JWT_SECRET=your-jwt-secret-key-here
JWT_TTL=60  # 60 minutes
JWT_REFRESH_TTL=10080  # 7 days

SANCTUM_STATEFUL_DOMAINS=localhost:3000
FRONTEND_URL=http://localhost:3000

CORS_ALLOWED_ORIGINS=http://localhost:3000
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization,X-Requested-With
```

## Configuration de la sécurité

### Middleware CORS

```php
// app/Http/Middleware/CorsMiddleware.php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class CorsMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $allowedOrigins = explode(',', env('CORS_ALLOWED_ORIGINS', 'http://localhost:3000'));

        if ($request->header('Origin') && in_array($request->header('Origin'), $allowedOrigins)) {
            return $next($request)
                ->header('Access-Control-Allow-Origin', $request->header('Origin'))
                ->header('Access-Control-Allow-Credentials', 'true')
                ->header('Access-Control-Allow-Methods', env('CORS_ALLOWED_METHODS', 'GET,POST,PUT,DELETE,OPTIONS'))
                ->header('Access-Control-Allow-Headers', env('CORS_ALLOWED_HEADERS', 'Content-Type,Authorization,X-Requested-With'))
                ->header('Access-Control-Max-Age', '86400');
        }

        return $next($request);
    }
}
```

### Configuration JWT

```php
// config/jwt.php
<?php

return [
    'secret' => env('JWT_SECRET'),
    'ttl' => env('JWT_TTL', 60),
    'refresh_ttl' => env('JWT_REFRESH_TTL', 10080),
    'algo' => 'HS256',
    'required_claims' => ['iss', 'iat', 'exp', 'sub'],
    'persistent_claims' => ['sub', 'role', 'permissions'],
];
```

## Modèles Eloquent

### Modèle User

```php
// app/Models/User.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Spatie\Permission\Traits\HasRoles;
use Illuminate\Database\Eloquent\SoftDeletes;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable, HasRoles, SoftDeletes;

    protected $fillable = [
        'first_name',
        'last_name',
        'email',
        'password',
        'is_active'
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'is_active' => 'boolean',
        'last_login_at' => 'datetime',
    ];

    // ✅ JWT methods
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [
            'role' => $this->roles->first()->name ?? 'user',
            'permissions' => $this->getAllPermissions()->pluck('name')->toArray()
        ];
    }

    // ✅ Relations
    public function posts()
    {
        return $this->hasMany(Post::class, 'author_id');
    }

    public function comments()
    {
        return $this->hasMany(Comment::class, 'author_id');
    }

    // ✅ Méthodes utilitaires
    public function getFullNameAttribute()
    {
        return "{$this->first_name} {$this->last_name}";
    }

    public function getIsAdminAttribute()
    {
        return $this->hasRole('admin');
    }

    public function getPermissionsAttribute()
    {
        return $this->getAllPermissions()->pluck('name')->toArray();
    }
}
```

### Modèle Post

```php
// app/Models/Post.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Post extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillable = [
        'title',
        'content',
        'excerpt',
        'status',
        'published_at',
        'author_id'
    ];

    protected $casts = [
        'published_at' => 'datetime',
        'view_count' => 'integer',
    ];

    protected $attributes = [
        'status' => 'draft',
        'view_count' => 0
    ];

    // ✅ Relations
    public function author()
    {
        return $this->belongsTo(User::class, 'author_id');
    }

    public function comments()
    {
        return $this->hasMany(Comment::class);
    }

    public function tags()
    {
        return $this->belongsToMany(Tag::class, 'post_tags');
    }

    // ✅ Scopes
    public function scopePublished($query)
    {
        return $query->where('status', 'published');
    }

    public function scopeDraft($query)
    {
        return $query->where('status', 'draft');
    }

    public function scopeByAuthor($query, $authorId)
    {
        return $query->where('author_id', $authorId);
    }

    // ✅ Méthodes utilitaires
    public function publish()
    {
        $this->update([
            'status' => 'published',
            'published_at' => now()
        ]);
    }

    public function unpublish()
    {
        $this->update([
            'status' => 'draft',
            'published_at' => null
        ]);
    }

    public function isPublished()
    {
        return $this->status === 'published' && !is_null($this->published_at);
    }

    public function incrementViews()
    {
        $this->increment('view_count');
    }
}
```

## Middleware d'authentification

### JWT Middleware

```php
// app/Http/Middleware/JWTMiddleware.php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class JWTMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user || !$user->is_active) {
                return response()->json([
                    'error' => 'authentication_failed',
                    'message' => 'User not found or inactive'
                ], 401);
            }

            $request->merge(['user' => $user]);
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'token_invalid',
                'message' => 'Token is invalid or expired'
            ], 401);
        }

        return $next($request);
    }
}
```

### Middleware d'autorisation

```php
// app/Http/Middleware/RoleMiddleware.php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RoleMiddleware
{
    public function handle(Request $request, Closure $next, ...$roles)
    {
        $user = $request->user();

        if (!$user) {
            return response()->json([
                'error' => 'authentication_required',
                'message' => 'Authentication required'
            ], 401);
        }

        if (!$user->hasAnyRole($roles)) {
            return response()->json([
                'error' => 'insufficient_permissions',
                'message' => 'Required roles: ' . implode(', ', $roles)
            ], 403);
        }

        return $next($request);
    }
}

// app/Http/Middleware/PermissionMiddleware.php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class PermissionMiddleware
{
    public function handle(Request $request, Closure $next, $permission)
    {
        $user = $request->user();

        if (!$user) {
            return response()->json([
                'error' => 'authentication_required',
                'message' => 'Authentication required'
            ], 401);
        }

        if (!$user->can($permission)) {
            return response()->json([
                'error' => 'insufficient_permissions',
                'message' => 'Required permission: ' . $permission
            ], 403);
        }

        return $next($request);
    }
}
```

## Contrôleurs

### Contrôleur d'authentification

```php
// app/Http/Controllers/Auth/LoginController.php
<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string'
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'invalid_credentials',
                'message' => 'Invalid email or password'
            ], 401);
        }

        if (!$user->is_active) {
            return response()->json([
                'error' => 'account_inactive',
                'message' => 'Your account has been deactivated'
            ], 401);
        }

        // Mettre à jour la dernière connexion
        $user->update(['last_login_at' => now()]);

        // Générer les tokens
        $accessToken = JWTAuth::fromUser($user);
        $refreshToken = JWTAuth::fromUser($user, ['type' => 'refresh']);

        return response()->json([
            'message' => 'Login successful',
            'user' => [
                'id' => $user->id,
                'email' => $user->email,
                'first_name' => $user->first_name,
                'last_name' => $user->last_name,
                'role' => $user->roles->first()->name ?? 'user'
            ],
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => config('jwt.ttl') * 60
        ]);
    }

    public function refresh(Request $request)
    {
        try {
            $token = JWTAuth::getToken();
            $payload = JWTAuth::getPayload($token)->toArray();

            if ($payload['type'] !== 'refresh') {
                return response()->json([
                    'error' => 'invalid_token_type',
                    'message' => 'Only refresh tokens are allowed'
                ], 401);
            }

            $user = JWTAuth::parseToken()->authenticate();
            $newToken = JWTAuth::fromUser($user);

            return response()->json([
                'access_token' => $newToken,
                'token_type' => 'Bearer',
                'expires_in' => config('jwt.ttl') * 60
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'invalid_token',
                'message' => 'Refresh token is invalid or expired'
            ], 401);
        }
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json([
                'message' => 'Logged out successfully'
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'logout_failed',
                'message' => 'Failed to logout'
            ], 500);
        }
    }
}
```

### Contrôleur des utilisateurs

```php
// app/Http/Controllers/UserController.php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use App\Http\Resources\UserResource;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('jwt.auth');
    }

    public function index(Request $request)
    {
        $query = User::query();

        // Pagination
        $perPage = min($request->get('limit', 20), 100);
        $page = $request->get('page', 1);

        // Filtres
        if ($request->has('search')) {
            $search = $request->get('search');
            $query->where(function($q) use ($search) {
                $q->where('first_name', 'like', "%{$search}%")
                  ->orWhere('last_name', 'like', "%{$search}%")
                  ->orWhere('email', 'like', "%{$search}%");
            });
        }

        if ($request->has('role')) {
            $query->whereHas('roles', function($q) use ($request) {
                $q->where('name', $request->get('role'));
            });
        }

        $users = $query->paginate($perPage, ['*'], 'page', $page);

        return response()->json([
            'data' => UserResource::collection($users),
            'pagination' => [
                'current_page' => $users->currentPage(),
                'per_page' => $users->perPage(),
                'total' => $users->total(),
                'last_page' => $users->lastPage(),
                'from' => $users->firstItem(),
                'to' => $users->lastItem()
            ],
            '_links' => [
                'self' => $request->fullUrl(),
                'first' => $request->url() . '?' . http_build_query(['page' => 1, 'limit' => $perPage]),
                'last' => $request->url() . '?' . http_build_query(['page' => $users->lastPage(), 'limit' => $perPage])
            ]
        ]);
    }

    public function show(Request $request, $id)
    {
        $currentUser = $request->user();

        // Vérification BOLA
        if ($id != $currentUser->id && !$currentUser->hasRole('admin')) {
            return response()->json([
                'error' => 'access_denied',
                'message' => 'You can only access your own profile'
            ], 403);
        }

        $user = User::with(['posts', 'comments'])->find($id);

        if (!$user) {
            return response()->json([
                'error' => 'user_not_found',
                'message' => 'No user found with this ID'
            ], 404);
        }

        return response()->json([
            'data' => new UserResource($user),
            '_links' => [
                'self' => route('users.show', $id),
                'posts' => route('posts.index', ['author_id' => $id])
            ]
        ]);
    }

    public function update(Request $request, $id)
    {
        $currentUser = $request->user();

        // Vérification BOLA
        if ($id != $currentUser->id && !$currentUser->hasRole('admin')) {
            return response()->json([
                'error' => 'access_denied',
                'message' => 'You can only modify your own profile'
            ], 403);
        }

        $request->validate([
            'first_name' => 'sometimes|required|string|max:50',
            'last_name' => 'sometimes|required|string|max:50',
            'email' => 'sometimes|required|email|unique:users,email,' . $id
        ]);

        $user = User::find($id);
        if (!$user) {
            return response()->json([
                'error' => 'user_not_found',
                'message' => 'No user found with this ID'
            ], 404);
        }

        $user->update($request->only(['first_name', 'last_name', 'email']));
        $user->load(['posts', 'comments']);

        return response()->json([
            'message' => 'User updated successfully',
            'data' => new UserResource($user)
        ]);
    }

    public function destroy(Request $request, $id)
    {
        $currentUser = $request->user();

        // Vérification BOLA et permissions
        if ($id != $currentUser->id && !$currentUser->hasRole('admin')) {
            return response()->json([
                'error' => 'access_denied',
                'message' => 'You can only delete your own account'
            ], 403);
        }

        $user = User::find($id);
        if (!$user) {
            return response()->json([
                'error' => 'user_not_found',
                'message' => 'No user found with this ID'
            ], 404);
        }

        $user->delete();

        return response()->json([
            'message' => 'User deleted successfully'
        ], 204);
    }
}
```

## Ressources API

### Ressource User

```php
// app/Http/Resources/UserResource.php
<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        $data = [
            'id' => $this->id,
            'first_name' => $this->first_name,
            'last_name' => $this->last_name,
            'full_name' => $this->full_name,
            'email' => $this->when($this->canAccessEmail($request->user()), $this->email),
            'role' => $this->when($request->user()->hasRole('admin'), $this->roles->first()->name),
            'is_active' => $this->is_active,
            'created_at' => $this->created_at->toISOString(),
            'updated_at' => $this->updated_at->toISOString()
        ];

        // Ajouter les relations si demandées
        if ($request->has('include')) {
            $includes = explode(',', $request->get('include'));

            if (in_array('posts', $includes)) {
                $data['posts'] = PostResource::collection($this->whenLoaded('posts'));
            }

            if (in_array('comments', $includes)) {
                $data['comments'] = CommentResource::collection($this->whenLoaded('comments'));
            }
        }

        return $data;
    }

    private function canAccessEmail($user): bool
    {
        return $user && ($this->id === $user->id || $user->hasRole('admin'));
    }
}
```

## Routes API

### Routes d'authentification

```php
// routes/api.php
<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\PostController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// ✅ Routes publiques
Route::prefix('auth')->group(function () {
    Route::post('register', [RegisterController::class, 'register']);
    Route::post('login', [LoginController::class, 'login']);
    Route::post('refresh', [LoginController::class, 'refresh']);
    Route::post('logout', [LoginController::class, 'logout'])->middleware('jwt.auth');
});

// ✅ Routes protégées
Route::middleware('jwt.auth')->group(function () {
    // Utilisateurs
    Route::apiResource('users', UserController::class);
    Route::get('users/{user}/posts', [UserController::class, 'posts']);

    // Articles
    Route::apiResource('posts', PostController::class);
    Route::post('posts/{post}/publish', [PostController::class, 'publish']);
    Route::post('posts/{post}/unpublish', [PostController::class, 'unpublish']);

    // Commentaires
    Route::apiResource('posts/{post}/comments', CommentController::class);
});

// ✅ Routes admin
Route::middleware(['jwt.auth', 'role:admin'])->prefix('admin')->group(function () {
    Route::get('users', [UserController::class, 'index']);
    Route::delete('users/{user}', [UserController::class, 'destroy']);
    Route::post('users/{user}/activate', [UserController::class, 'activate']);
    Route::post('users/{user}/deactivate', [UserController::class, 'deactivate']);
});

// ✅ Health check
Route::get('health', function () {
    return response()->json([
        'status' => 'healthy',
        'timestamp' => now()->toISOString(),
        'version' => config('app.version', '1.0.0')
    ]);
});
```

## Validation des requêtes

### Request Classes

```php
// app/Http/Requests/StoreUserRequest.php
<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Password;

class StoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'email' => ['required', 'email', 'unique:users,email'],
            'password' => [
                'required',
                'confirmed',
                Password::min(8)
                    ->letters()
                    ->mixedCase()
                    ->numbers()
                    ->symbols()
            ],
            'first_name' => ['required', 'string', 'min:2', 'max:50'],
            'last_name' => ['required', 'string', 'min:2', 'max:50'],
            'role' => ['sometimes', 'in:user,author,admin']
        ];
    }

    public function messages(): array
    {
        return [
            'email.required' => 'Email is required',
            'email.email' => 'Please provide a valid email address',
            'email.unique' => 'This email is already registered',
            'password.required' => 'Password is required',
            'password.confirmed' => 'Password confirmation does not match',
            'password.min' => 'Password must be at least 8 characters',
            'first_name.required' => 'First name is required',
            'first_name.min' => 'First name must be at least 2 characters',
            'last_name.required' => 'Last name is required',
            'last_name.min' => 'Last name must be at least 2 characters'
        ];
    }
}
```

## Tests

### Tests d'authentification

```php
// tests/Feature/AuthTest.php
<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use App\Models\User;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_register()
    {
        $response = $this->postJson('/api/auth/register', [
            'email' => 'test@example.com',
            'password' => 'SecurePass123!',
            'password_confirmation' => 'SecurePass123!',
            'first_name' => 'Test',
            'last_name' => 'User'
        ]);

        $response->assertStatus(201)
                ->assertJsonStructure([
                    'message',
                    'user' => ['id', 'email', 'first_name', 'last_name'],
                    'access_token',
                    'refresh_token'
                ]);
    }

    public function test_user_can_login()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password123')
        ]);

        $response = $this->postJson('/api/auth/login', [
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);

        $response->assertStatus(200)
                ->assertJsonStructure([
                    'message',
                    'user',
                    'access_token',
                    'refresh_token'
                ]);
    }

    public function test_user_can_access_protected_route()
    {
        $user = User::factory()->create();
        $token = auth('api')->fromUser($user);

        $response = $this->getJson('/api/users/' . $user->id, [
            'Authorization' => 'Bearer ' . $token
        ]);

        $response->assertStatus(200)
                ->assertJsonStructure([
                    'data' => ['id', 'first_name', 'last_name', 'email']
                ]);
    }

    public function test_unauthorized_access_is_denied()
    {
        $response = $this->getJson('/api/users/1');

        $response->assertStatus(401)
                ->assertJson([
                    'error' => 'token_invalid'
                ]);
    }
}
```

### Tests BOLA

```php
// tests/Feature/SecurityTest.php
<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use App\Models\User;

class SecurityTest extends TestCase
{
    use RefreshDatabase;

    public function test_bola_prevention_user_data()
    {
        $user1 = User::factory()->create();
        $user2 = User::factory()->create();

        $token = auth('api')->fromUser($user1);

        // Tentative d'accès aux données d'un autre utilisateur
        $response = $this->getJson('/api/users/' . $user2->id, [
            'Authorization' => 'Bearer ' . $token
        ]);

        $response->assertStatus(403)
                ->assertJson([
                    'error' => 'access_denied',
                    'message' => 'You can only access your own profile'
                ]);
    }

    public function test_admin_can_access_all_users()
    {
        $admin = User::factory()->create();
        $admin->assignRole('admin');

        $user = User::factory()->create();

        $token = auth('api')->fromUser($admin);

        $response = $this->getJson('/api/users/' . $user->id, [
            'Authorization' => 'Bearer ' . $token
        ]);

        $response->assertStatus(200)
                ->assertJsonStructure([
                    'data' => ['id', 'first_name', 'last_name', 'email', 'role']
                ]);
    }
}
```

## Documentation avec Swagger

### Configuration L5-Swagger

```bash
composer require --dev l5-swagger
php artisan vendor:publish --provider="L5Swagger\L5SwaggerServiceProvider"
```

### Annotations dans les contrôleurs

```php
// app/Http/Controllers/UserController.php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use App\Http\Resources\UserResource;

/**
 * @OA\Info(
 *     title="Blog API",
 *     version="1.0.0",
 *     description="REST API for a blog platform"
 * )
 *
 * @OA\Server(
 *     url="http://localhost:8000/api",
 *     description="Development server"
 * )
 */
class UserController extends Controller
{
    /**
     * @OA\Get(
     *     path="/users",
     *     summary="Get all users",
     *     description="Retrieve a paginated list of users",
     *     operationId="getUsers",
     *     tags={"Users"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page number",
     *         @OA\Schema(type="integer", minimum=1, default=1)
     *     ),
     *
     *     @OA\Parameter(
     *         name="limit",
     *         in="query",
     *         description="Items per page",
     *         @OA\Schema(type="integer", minimum=1, maximum=100, default=20)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="List of users",
     *         @OA\JsonContent(
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/User")),
     *             @OA\Property(property="pagination", ref="#/components/schemas/Pagination")
     *         )
     *     ),
     *
     *     @OA\Response(response=401, description="Unauthorized")
     * )
     */
    public function index(Request $request) { /* ... */ }
}
```

## Quiz PHP et Laravel

**Question 1** : Quel est l'avantage principal de Laravel pour les APIs ?
**Réponse** : Écosystème complet avec authentification, autorisation et validation intégrées

**Question 2** : Comment implémenter l'authentification JWT dans Laravel ?
**Réponse** : Avec le package tymon/jwt-auth et le middleware JWT

**Question 3** : Comment gérer les permissions dans Laravel ?
**Réponse** : Avec le package spatie/laravel-permission et les rôles/permissions

## En résumé

### Avantages de Laravel
- 🎯 **Framework mature** et stable
- 🔧 **Outils intégrés** (Artisan, Eloquent, etc.)
- 🔒 **Sécurité** (CSRF, XSS, SQL injection)
- 📚 **Documentation** extensive
- 🧪 **Tests** avec PHPUnit
- 🌐 **Communauté** active

### Structure recommandée
```
app/
├── Http/Controllers/    # Contrôleurs
├── Http/Middleware/     # Middleware
├── Http/Requests/       # Validation
├── Http/Resources/      # Ressources API
├── Models/             # Modèles Eloquent
└── Providers/          # Services
```

### Bonnes pratiques
- ✅ **Validation** avec Form Requests
- ✅ **Middleware** pour auth et autorisation
- ✅ **Ressources** pour la transformation
- ✅ **Policies** pour l'autorisation
- ✅ **Tests** avec PHPUnit
- ✅ **Documentation** avec L5-Swagger

### Configuration complète
```php
// Laravel moderne
✅ Eloquent ORM
✅ JWT Authentication
✅ Role-based Authorization
✅ Request Validation
✅ API Resources
✅ Middleware Security
✅ Rate Limiting
✅ CORS Support
✅ Tests automatisés
```

Dans le dernier chapitre de cette section, nous verrons comment **tester** une API REST avec Postman et des tests unitaires !

---

**Prochain chapitre** : [04-Tests-Unitaires-et-Postman](04-Tests-Unitaires-et-Postman.md)
