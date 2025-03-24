package org.tkit.onecx.iam.kc.rs.external.v1.controllers;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;
import org.tkit.onecx.iam.kc.domain.service.KeycloakAdminService;
import org.tkit.onecx.iam.kc.domain.service.KeycloakException;
import org.tkit.onecx.iam.kc.rs.external.v1.mappers.ExceptionMapper;
import org.tkit.onecx.iam.kc.rs.external.v1.mappers.RoleMapper;
import org.tkit.quarkus.log.cdi.LogService;

import gen.org.tkit.onecx.iam.kc.v1.AdminControllerApi;
import gen.org.tkit.onecx.iam.kc.v1.model.ProblemDetailResponseDTOV1;
import gen.org.tkit.onecx.iam.kc.v1.model.UserRolesSearchRequestDTOV1;

@LogService
@ApplicationScoped
public class AdminRestControllerV1 implements AdminControllerApi {

    @Inject
    KeycloakAdminService adminService;

    @Inject
    ExceptionMapper exceptionMapper;

    @Inject
    RoleMapper mapper;

    @Override
    public Response getUserRoles(String userId, UserRolesSearchRequestDTOV1 userRolesSearchRequestDTOV1) {
        return Response.ok().entity(mapper.map(adminService.getUserRoles(userRolesSearchRequestDTOV1.getIssuer(), userId)))
                .build();
    }

    @Override
    public Response validateIssuer(String issuer) {
        var provider = adminService.validateIssuer(issuer);
        if (provider == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        } else {
            return Response.status(Response.Status.OK).build();
        }
    }

    @ServerExceptionMapper
    public RestResponse<ProblemDetailResponseDTOV1> constraint(KeycloakException ex) {
        return exceptionMapper.exception(ex);
    }

}
