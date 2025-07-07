<?php

class jwt{




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