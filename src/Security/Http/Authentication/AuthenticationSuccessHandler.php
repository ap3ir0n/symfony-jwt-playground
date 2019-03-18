<?php

namespace App\Security\Http\Authentication;

use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationSuccessEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Events;
use Lexik\Bundle\JWTAuthenticationBundle\Response\JWTAuthenticationSuccessResponse;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManager;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

/**
 * AuthenticationSuccessHandler.
 *
 * @author Dev Lexik <dev@lexik.fr>
 */
class AuthenticationSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    /**
     * @var JWTManager
     */
    protected $jwtManager;

    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @var RouterInterface
     */
    protected $router;

    /**
     * @param JWTTokenManagerInterface $jwtManager
     * @param EventDispatcherInterface $dispatcher
     * @param RouterInterface $router
     */
    public function __construct(
        JWTTokenManagerInterface $jwtManager,
        EventDispatcherInterface $dispatcher,
        RouterInterface $router
    )
    {
        $this->jwtManager = $jwtManager;
        $this->dispatcher = $dispatcher;
        $this->router = $router;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        return $this->handleAuthenticationSuccess($token->getUser());
    }

    public function handleAuthenticationSuccess(UserInterface $user, $jwt = null)
    {
        if (null === $jwt) {
            $jwt = $this->jwtManager->create($user);
        }

        $response = new RedirectResponse($this->router->generate('web_secured'));
        $event    = new AuthenticationSuccessEvent(['token' => $jwt], $user, $response);

        $this->dispatcher->dispatch(Events::AUTHENTICATION_SUCCESS, $event);

        $response->headers->setCookie(new Cookie('jwt', $jwt));

        return $response;
    }
}
