package org.tkit.onecx.iam.kc.domain.service;

public class KeycloakRealmNameUtil {

    private KeycloakRealmNameUtil() {
    }

    static String getRealmName(String issuer) {
        int index = issuer.lastIndexOf("/");
        if (index >= 0) {
            return issuer.substring(index + 1);
        }
        throw new KeycloakException("Wrong issuer format");
    }

}
