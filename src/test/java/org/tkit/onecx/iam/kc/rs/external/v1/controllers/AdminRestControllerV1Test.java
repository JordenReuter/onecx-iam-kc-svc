package org.tkit.onecx.iam.kc.rs.external.v1.controllers;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

import java.io.IOException;
import java.util.Base64;

import jakarta.ws.rs.core.Response;

import org.jose4j.json.internal.json_simple.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.tkit.onecx.iam.kc.test.AbstractTest;
import org.tkit.quarkus.security.test.GenerateKeycloakClient;

import com.fasterxml.jackson.databind.ObjectMapper;

import gen.org.tkit.onecx.iam.kc.v1.model.UserRolesResponseDTOV1;
import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.keycloak.client.KeycloakTestClient;

@QuarkusTest
@TestHTTPEndpoint(AdminRestControllerV1.class)
@GenerateKeycloakClient(clientName = "testClient", scopes = { "ocx-ia:read", "ocx-ia:write" })
class AdminRestControllerV1Test extends AbstractTest {

    private static final KeycloakTestClient keycloakAuthClient = new KeycloakTestClient();
    KeycloakTestClient keycloakClient = createClient();

    @Test
    void getUserRolesTest() throws IOException {
        var tokens = this.getTokens(keycloakClient, USER_ALICE);
        var aliceToken = tokens.getIdToken();
        ObjectMapper mapper = new ObjectMapper();
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] chunks = aliceToken.split("\\.");
        String body = new String(decoder.decode(chunks[1]));
        JSONObject jwt = mapper.readValue(body, JSONObject.class);

        String id = jwt.get("sub").toString();

        var result = given()
                .auth().oauth2(keycloakAuthClient.getClientAccessToken("testClient"))
                .header(APM_HEADER_TOKEN, aliceToken)
                .pathParam("provider", "kc0")
                .pathParam("domain", "quarkus")
                .pathParam("userId", id)
                .contentType(APPLICATION_JSON).get()
                .then().statusCode(Response.Status.OK.getStatusCode())
                .extract().as(UserRolesResponseDTOV1.class);
        Assertions.assertNotNull(result);
        Assertions.assertEquals(2, result.getRoles().size());

        //user not found:
        given()
                .auth().oauth2(keycloakAuthClient.getClientAccessToken("testClient"))
                .header(APM_HEADER_TOKEN, aliceToken)
                .pathParam("provider", "kc0")
                .pathParam("domain", "master")
                .pathParam("userId", id)
                .contentType(APPLICATION_JSON).get()
                .then().statusCode(Response.Status.BAD_REQUEST.getStatusCode());

        //no token test
        given()
                .auth().oauth2(keycloakAuthClient.getClientAccessToken("testClient"))
                .pathParam("provider", "kc0")
                .pathParam("domain", "master")
                .pathParam("userId", id)
                .contentType(APPLICATION_JSON).get()
                .then().statusCode(Response.Status.BAD_REQUEST.getStatusCode());
    }
}
