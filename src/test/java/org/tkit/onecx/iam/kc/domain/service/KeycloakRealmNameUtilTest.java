package org.tkit.onecx.iam.kc.domain.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.tkit.onecx.iam.kc.test.AbstractTest;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
class KeycloakRealmNameUtilTest extends AbstractTest {

    @Test
    void realmNameTest() {
        Assertions.assertThrowsExactly(KeycloakException.class, () -> KeycloakRealmNameUtil.getRealmName(""));
    }
}
