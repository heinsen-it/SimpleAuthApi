<?php

class jwt{


    /**
     * Dekodiert und verifiziert ein JWT Token
     *
     * @param string $jwt Das zu dekodierende Token
     * @param string $key Schlüssel für die Verifikation (bei RSA: öffentlicher Schlüssel)
     * @param array $allowedAlgorithms Erlaubte Algorithmen (Standard: nur HS256)
     * @return object Die dekodierten Daten als Objekt
     * @throws Exception Bei ungültigem Token oder fehlgeschlagener Verifikation
     */
    public static function decode(string $jwt, string $key, array $allowedAlgorithms = ['HS256']): object {
        $timestamp = time();

        // Überprüfung der Eingabeparameter
        if (empty($key)) {
            throw new Exception('Schlüssel darf nicht leer sein');
        }

        // Token in seine Bestandteile zerlegen
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            throw new Exception('Ungültiges Token-Format');
        }

        list($headerB64, $payloadB64, $signatureB64) = $segments;

        // Header dekodieren und überprüfen
        $header = json_decode(self::urlsafeB64Decode($headerB64));
        if ($header === null) {
            throw new Exception('Ungültiger Header-Encoding');
        }

        // Payload dekodieren und überprüfen
        $payload = json_decode(self::urlsafeB64Decode($payloadB64));
        if ($payload === null) {
            throw new Exception('Ungültiger Payload-Encoding');
        }

        // Signatur dekodieren
        $signature = self::urlsafeB64Decode($signatureB64);
        if ($signature === false) {
            throw new Exception('Ungültige Signatur-Encoding');
        }

        // Algorithmus überprüfen
        if (empty($header->alg)) {
            throw new Exception('Algorithmus nicht spezifiziert');
        }

        if (!in_array($header->alg, $allowedAlgorithms, true)) {
            throw new Exception('Algorithmus nicht erlaubt: ' . $header->alg);
        }

        if (!isset(self::$supportedAlgorithms[$header->alg])) {
            throw new Exception('Algorithmus wird nicht unterstützt: ' . $header->alg);
        }

        // Signatur überprüfen
        if (!self::verify("$headerB64.$payloadB64", $signature, $key, $header->alg)) {
            throw new Exception('Signatur-Verifikation fehlgeschlagen');
        }

        // Standard-Claims überprüfen

        // exp (Expiration Time) - Ablaufzeit
        if (isset($payload->exp) && ($payload->exp + self::$leeway) < $timestamp) {
            throw new Exception('Token ist abgelaufen');
        }

        // nbf (Not Before) - Nicht vor
        if (isset($payload->nbf) && $payload->nbf > ($timestamp + self::$leeway)) {
            throw new Exception('Token ist noch nicht gültig');
        }

        // iat (Issued At) - Ausstellungszeitpunkt
        if (isset($payload->iat) && $payload->iat > ($timestamp + self::$leeway)) {
            throw new Exception('Token wurde in der Zukunft ausgestellt');
        }

        return $payload;
    }

    /**
     * Validiert einen JWT ohne ihn zu dekodieren (prüft nur Signatur und Zeitstempel)
     *
     * @param string $jwt Token zum Validieren
     * @param string $key Schlüssel für die Verifikation
     * @param array $allowedAlgorithms Erlaubte Algorithmen
     * @return bool True wenn Token gültig ist
     */
    public static function validate(string $jwt, string $key, array $allowedAlgorithms = ['HS256']): bool {
        try {
            self::decode($jwt, $key, $allowedAlgorithms);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Dekodiert ein JWT Token ohne Signaturprüfung (unsicher - nur für Debugging!)
     *
     * @param string $jwt Das zu dekodierende Token
     * @return object Die dekodierten Daten
     * @throws Exception Bei ungültigem Token-Format
     */
    public static function decodeInsecure(string $jwt): object {
        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new Exception('Ungültiges Token-Format');
        }

        list($headerB64, $payloadB64) = $segments;

        $payload = json_decode(self::urlsafeB64Decode($payloadB64));
        if ($payload === null) {
            throw new Exception('Ungültiger Payload-Encoding');
        }

        return $payload;
    }


    /**
     * Signiert die Daten mit dem angegebenen Algorithmus
     *
     * @param string $input Daten zum Signieren
     * @param string $key Schlüssel für die Signierung
     * @param string $algorithm Algorithmus
     * @return string Die erzeugte Signatur
     * @throws Exception Bei Fehler in der Signierung
     */
    private static function sign(string $input, string $key, string $algorithm): string {
        list($function, $algo) = self::$supportedAlgorithms[$algorithm];

        switch ($function) {
            case 'hash_hmac':
                return hash_hmac($algo, $input, $key, true);

            case 'openssl':
                $signature = '';
                $success = openssl_sign($input, $signature, $key, $algo);
                if (!$success) {
                    throw new Exception('OpenSSL konnte nicht signieren: ' . openssl_error_string());
                }
                return $signature;

            default:
                throw new Exception('Nicht unterstützte Signierungsfunktion');
        }
    }



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