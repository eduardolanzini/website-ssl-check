<?php

$sites = include 'sites-list.php';

function verificaSSL($url) {

    $parsedUrl = parse_url($url);
    $host = $parsedUrl['host'] ?? $url;
    
    $url = "https://" . $host;

    $context = stream_context_create([
        "ssl" => [
            "capture_peer_cert" => true,
            "verify_peer" => true,
            "verify_peer_name" => true,
        ],
    ]);

    $stream = @stream_socket_client(
        "ssl://" . $host . ":443",
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if (!$stream) {
        return [
            'success' => false,
            'msg' => "Erro ao verificar SSL: $errstr ($errno)"
        ];
    }

    $params = stream_context_get_params($stream);

    if(!isset($params["options"]["ssl"]["peer_certificate"])){
        return [
            'success' => false,
            'msg' => "Certificado SSL não encontrado no stream."
        ];
    }

    $certinfo = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);

    if ($certinfo && isset($certinfo['validTo_time_t'])) {
        $validTo = $certinfo['validTo_time_t'];
        if ($validTo >= time()) {
            return [
                'success' => true,
                'msg' => "Certificado SSL válido.",
                'validTo' => date('Y-m-d H:i:s', $validTo)
            ];
        } else {
            return [
                'success' => false,
                'msg' => "Certificado SSL expirado.",
                'validTo' => date('Y-m-d H:i:s', $validTo)
            ];
        }
    }

    return [
        'success' => false,
        'msg' => "Erro ao analisar o certificado SSL."
    ];
    
}

if (!is_dir('logs')) {
    mkdir('logs', 0755, true);
}

$logFile = "logs/test-log-" . date('Y-m-d H-i-s') . ".log";

$sitesComSSL = [];
$sitesSemSSL = [];

foreach ($sites as $site) {

    $sslVerificado = verificaSSL($site);

    if ($sslVerificado['success']) {
        $msg = "$site tem SSL válido. Certificado válido até {$sslVerificado['validTo']}";
        $sitesComSSL[] = $msg;
        echo "\033[32m" . $msg . "\033[0m\n";
    } else {
        $msg = "$site não tem SSL válido - {$sslVerificado['msg']}";
        $sitesSemSSL[] = $msg;
        echo "\033[31m" . $msg . "\033[0m\n";
    }
}

file_put_contents($logFile, "=== Sites com SSL Válido ===\n", FILE_APPEND);
file_put_contents($logFile, implode("\n", $sitesComSSL) . "\n\n", FILE_APPEND);
file_put_contents($logFile, "=== Sites sem SSL ===\n", FILE_APPEND);
file_put_contents($logFile, implode("\n", $sitesSemSSL) . "\n", FILE_APPEND);

echo "\n\n\033[1mResultados registrados no arquivo de log: $logFile\033[0m\n";

?>