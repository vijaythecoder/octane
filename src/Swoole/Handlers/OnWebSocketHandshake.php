<?php

namespace Laravel\Octane\Swoole\Handlers;

use Laravel\Octane\Swoole\WorkerState;
use Swoole\WebSocket\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

class OnWebSocketHandshake
{
    // Constructor accepts a Server instance, a serverState array, and a WorkerState instance
    public function __construct(protected Server $server,
                                protected array $serverState,
                                protected WorkerState $workerState)
    {
    }

    /**
     * Handle the "handshake" Swoole event.
     *
     * @param Request $request
     * @param Response $response
     * @return bool
     */
    public function __invoke(Request $request, Response $response): bool
    {
        // Retrieve the 'sec-websocket-key' from the request headers
        $secWebSocketKey = $request->header['sec-websocket-key'];
        $patten = '#^[+/0-9A-Za-z]{21}[AQgw]==$#';

        // Validate the 'sec-websocket-key'
        if (0 === preg_match($patten, $secWebSocketKey) || 16 !== strlen(base64_decode($secWebSocketKey))) {
            // If the key is invalid, end the response and return false
            $response->end();
            return false;
        }

        // If the key is valid, combine it with a magic string, hash it with SHA1, and base64 encode it
        $key = base64_encode(sha1($request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));

        // Prepare the headers for the response
        $headers = [
            'upgrade' => 'websocket',
            'connection' => 'Upgrade',
            'sec-webSocket-Accept' => $key,
            'sec-webSocket-Version' => '13',
        ];

        // If the request includes a 'sec-websocket-protocol' header, include it in the response
        if (isset($request->header['sec-websocket-protocol'])) {
            $headers['sec-webSocket-Protocol'] = $request->header['sec-websocket-protocol'];
        }

        // Set the headers on the response
        foreach ($headers as $key => $val) {
            $response->header($key, $val);
        }

        // Set the response status to 101 (Switching Protocols) and end the response
        $response->status(101);
        $response->end();

        // Return true to indicate that the handshake was successful
        return true;
    }
}
