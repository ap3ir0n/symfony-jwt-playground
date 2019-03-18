<?php
declare(strict_types=1);

namespace App\Controller;


use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class WebController
{
    public function securedAction(Request $request)
    {
        return Response::create('<h1>Secured route</h1>');
    }

    public function unsecuredAction(Request $request)
    {
        return Response::create('<h1>Unsecured route</h1>');
    }
}