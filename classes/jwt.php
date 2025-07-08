<?php

class jwt{




    /**
     * Verifiziert die Signatur eines JWT
     *
     * @param string $input Daten, die signiert wurden
     * @param string $signature Zu überprüfende Signatur
     * @param string $key Schlüssel für die Verifikation
     * @param string $algorithm Verwendeter Algorithmus
     * @return bool True wenn die Signatur gültig ist
     * @throws Exception Bei Fehler in der Verifikation
     */
    private static function verify(string $input, string $signature, string $key, string $algorithm): bool {
        list($function, $algo) = self::$supportedAlgorithms[$algorithm];

        switch ($function) {
            case 'hash_hmac':
                $hash = hash_hmac($algo, $input, $key, true);
                return hash_equals($hash, $signature);

            case 'openssl':
                $result = openssl_verify($input, $signature, $key, $algo);
                if ($result === -1) {
                    throw new Exception('OpenSSL-Fehler: ' . openssl_error_string());
                }
                return $result === 1;

            default:
                throw new Exception('Nicht unterstützte Verifikationsfunktion');
        }
    }

    /**
     * Erzeugt eine Base64Url-Kodierung
     *
     * @param string $data Zu kodierende Daten
     * @return string Base64Url-kodierte Daten
     */
    private static function urlsafeB64Encode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Dekodiert Base64Url-kodierte Daten
     *
     * @param string $data Zu dekodierende Daten
     * @return string|false Dekodierte Daten oder False bei Fehler
     */
    private static function urlsafeB64Decode(string $data) {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}