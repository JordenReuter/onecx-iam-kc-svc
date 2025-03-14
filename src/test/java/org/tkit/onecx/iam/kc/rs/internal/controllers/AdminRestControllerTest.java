package org.tkit.onecx.iam.kc.rs.internal.controllers;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.assertj.core.api.Assertions.assertThat;
import static org.tkit.onecx.iam.kc.rs.internal.mappers.ExceptionMapper.ErrorKeys.CONSTRAINT_VIOLATIONS;
import static org.tkit.quarkus.rs.context.token.TokenParserService.ErrorKeys.ERROR_PARSE_TOKEN;

import java.io.IOException;
import java.util.Base64;

import jakarta.ws.rs.core.Response;

import org.jose4j.json.internal.json_simple.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.tkit.onecx.iam.kc.rs.internal.mappers.ExceptionMapper;
import org.tkit.onecx.iam.kc.test.AbstractTest;
import org.tkit.quarkus.security.test.GenerateKeycloakClient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gen.org.tkit.onecx.iam.kc.internal.model.*;
import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.keycloak.client.KeycloakTestClient;
import io.restassured.http.ContentType;

@QuarkusTest
@TestHTTPEndpoint(AdminRestController.class)
@GenerateKeycloakClient(clientName = "testClient", scopes = { "ocx-ia:read", "ocx-ia:write", "ocx-ia:all" })
public class AdminRestControllerTest extends AbstractTest {
    KeycloakTestClient authClient = new KeycloakTestClient();
    KeycloakTestClient keycloakClient = createClient();
    //KeycloakTestClient keycloakClient1 = createClient1();

    @Test
    void getAllKeycloaksAndRealms_Test() {
        var kc0_token = this.getTokens(keycloakClient, USER_ALICE).getIdToken();
        var res = given().when()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .header(APM_HEADER_TOKEN, kc0_token)
                .contentType(ContentType.JSON)
                .get("/providers")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract().as(ProvidersResponseDTO.class);
        Assertions.assertNotNull(res);
        Assertions.assertEquals(2, res.getProviders().size());
    }

    @Test
    void roleSearchAllTest() {

        var result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(new RoleSearchCriteriaDTO())
                .pathParam("provider", "kc1")
                .pathParam("realm", "master")
                .post("/{provider}/{realm}/roles/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(RolePageResultDTO.class);
        assertThat(result).isNotNull();
        assertThat(result.getStream()).isNotNull().isNotEmpty().hasSize(5);
    }

    @Test
    void roleSearchTest() {
        var result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(new RoleSearchCriteriaDTO().name("default-roles-master"))
                .pathParam("provider", "kc1")
                .pathParam("realm", "master")
                .post("/{provider}/{realm}/roles/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(RolePageResultDTO.class);

        assertThat(result).isNotNull();
        assertThat(result.getStream()).isNotNull()
                .hasSize(1);

        //search in wrong kc and realm
        given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(new RoleSearchCriteriaDTO().name("default-roles-master"))
                .pathParam("provider", "kc100")
                .pathParam("realm", "someRealm")
                .post("/{provider}/{realm}/roles/search")
                .then()
                .statusCode(Response.Status.BAD_REQUEST.getStatusCode());
    }

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
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .header(APM_HEADER_TOKEN, aliceToken)
                .contentType(APPLICATION_JSON)
                .pathParam("provider", "kc0")
                .pathParam("realm", "quarkus")
                .pathParam("userId", id)
                .get("/{provider}/{realm}/roles/{userId}")
                .then().statusCode(Response.Status.OK.getStatusCode())
                .extract().as(UserRolesResponseDTO.class);
        Assertions.assertNotNull(result);
        Assertions.assertEquals(2, result.getRoles().size());

        //not existing kc and realm
        given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .header(APM_HEADER_TOKEN, aliceToken)
                .contentType(APPLICATION_JSON)
                .pathParam("provider", "kc100")
                .pathParam("realm", "someRealm")
                .pathParam("userId", id)
                .get("/{provider}/{realm}/roles/{userId}")
                .then().statusCode(Response.Status.BAD_REQUEST.getStatusCode())
                .extract().as(ProblemDetailResponseDTO.class);
    }

    @Test
    void roleSearchNoBodyTest() {

        var exception = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .pathParam("provider", "kc0")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/roles/search")
                .then()
                .statusCode(Response.Status.BAD_REQUEST.getStatusCode())
                .extract()
                .body().as(ProblemDetailResponseDTO.class);

        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isNotNull().isEqualTo(ExceptionMapper.ErrorKeys.CONSTRAINT_VIOLATIONS.name());
        assertThat(exception.getDetail()).isNotNull()
                .isEqualTo("searchRolesByCriteria.roleSearchCriteriaDTO: must not be null");
        assertThat(exception.getInvalidParams()).isNotNull().isNotEmpty();
    }

    @Test
    void roleSearchEmptyResultTest() {

        var result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(new RoleSearchCriteriaDTO().name("does-not-exists"))
                .pathParam("provider", "kc0")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/roles/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(RolePageResultDTO.class);

        assertThat(result).isNotNull();
        assertThat(result.getStream()).isNotNull().isEmpty();
    }

    @Test
    void searchUsersRequest() throws JsonProcessingException {

        UserSearchCriteriaDTO dto = new UserSearchCriteriaDTO();
        dto.setUserName("alice");

        var result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(dto)
                .pathParam("provider", "kc1")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(UserPageResultDTO.class);

        Assertions.assertNotNull(result);
        Assertions.assertEquals(1, result.getTotalElements());
        Assertions.assertNotNull(result.getStream());
        Assertions.assertEquals(1, result.getStream().size());
        Assertions.assertEquals("alice", result.getStream().get(0).getUsername());
        dto.setUserId(result.getStream().get(0).getId());

        result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(dto)
                .pathParam("provider", "kc1")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(UserPageResultDTO.class);
        Assertions.assertEquals(1, result.getTotalElements());
        dto.setUserId("");

        result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(dto)
                .pathParam("provider", "kc0")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(UserPageResultDTO.class);
        Assertions.assertEquals(1, result.getTotalElements());

        //search by id in correct kc
        var tokens = this.getTokens(keycloakClient, USER_ALICE);
        var aliceToken = tokens.getIdToken();
        ObjectMapper mapper = new ObjectMapper();
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] chunks = aliceToken.split("\\.");
        String body = new String(decoder.decode(chunks[1]));
        JSONObject jwt = mapper.readValue(body, JSONObject.class);

        dto.setUserId(jwt.get("sub").toString());

        result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(dto)
                .pathParam("provider", "kc0")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(UserPageResultDTO.class);
        Assertions.assertEquals(1, result.getTotalElements());
        //search in wrong kc => user with given id does not exist
        result = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(dto)
                .pathParam("provider", "kc1")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract()
                .body().as(UserPageResultDTO.class);
        Assertions.assertEquals(0, result.getTotalElements());

        //search in not existing kc and realm
        given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, this.getTokens(keycloakClient, USER_ALICE).getIdToken())
                .body(dto)
                .pathParam("provider", "kc100")
                .pathParam("realm", "someRealm")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.BAD_REQUEST.getStatusCode());
    }

    @Test
    void searchUsersEmptyToken() {

        UserSearchCriteriaDTO dto = new UserSearchCriteriaDTO();

        var exception = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .header(APM_HEADER_TOKEN, " ")
                .body(dto)
                .pathParam("provider", "kc0")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.BAD_REQUEST.getStatusCode())
                .extract()
                .body().as(ProblemDetailResponseDTO.class);
        Assertions.assertNotNull(exception);
        Assertions.assertEquals(ERROR_PARSE_TOKEN.name(), exception.getErrorCode());
        Assertions.assertEquals(
                "Error parse raw token",
                exception.getDetail());
        assertThat(exception.getInvalidParams()).isNotNull().isEmpty();

    }

    @Test
    void searchUsersNoRequest() {

        var exception = given()
                .auth().oauth2(authClient.getClientAccessToken("testClient"))
                .contentType(APPLICATION_JSON)
                .pathParam("provider", "kc0")
                .pathParam("realm", "quarkus")
                .post("/{provider}/{realm}/users/search")
                .then()
                .statusCode(Response.Status.BAD_REQUEST.getStatusCode())
                .extract()
                .body().as(ProblemDetailResponseDTO.class);

        Assertions.assertNotNull(exception);
        Assertions.assertEquals(CONSTRAINT_VIOLATIONS.name(), exception.getErrorCode());
        Assertions.assertEquals(
                "searchUsersByCriteria.userSearchCriteriaDTO: must not be null",
                exception.getDetail());
        Assertions.assertNotNull(exception.getInvalidParams());
    }
}
