package org.tkit.onecx.iam.kc.domain.config;

import java.util.Map;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigDocFilename;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithName;

/**
 * Iam kc svc configuration
 */
@ConfigDocFilename("onecx-iam-kc-svc.adoc")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
@ConfigMapping(prefix = "onecx.kc")
public interface KcConfig {

    /**
     * Keycloak configurations
     */
    @WithName("keycloaks")
    Map<String, ClientConfig> keycloaks();

    /**
     * Keycloak client configurations
     */
    interface ClientConfig {
        /**
         * Description for keycloak
         */
        @WithName("description")
        Optional<String> description();

        /**
         * url of keycloak
         */
        @WithName("url")
        String url();

        /**
         * Baseurl of keycloak
         */
        @WithName("issuerHost")
        String issuerHost();

        /**
         * Keycloak realm
         */
        @WithName("realm")
        String realm();

        /**
         * Client for keylcloak admin api
         */
        @WithName("client")
        String clientId();

        /**
         * Client secret
         */
        @WithName("secret")
        String clientSecret();

        /**
         * Username for keycloak admin api access
         */
        @WithName("username")
        String username();

        /**
         * User password
         */
        @WithName("password")
        String password();
    }
}
