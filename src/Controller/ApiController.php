<?php
declare(strict_types=1);

namespace App\Controller;


use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class ApiController
{
    public function securedAction(Request $request)
    {
        return JsonResponse::create([
            'route' => 'secured'
        ]);
    }

    public function unsecuredAction(Request $request)
    {
        return JsonResponse::create([
            'route' => 'unsecured'
        ]);
    }
}