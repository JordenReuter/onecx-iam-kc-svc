package org.tkit.onecx.iam.kc.rs.internal.controllers;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Response;

import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;
import org.tkit.onecx.iam.kc.domain.service.KeycloakAdminService;
import org.tkit.onecx.iam.kc.domain.service.KeycloakException;
import org.tkit.onecx.iam.kc.rs.internal.mappers.ExceptionMapper;
import org.tkit.onecx.iam.kc.rs.internal.mappers.RoleMapper;
import org.tkit.onecx.iam.kc.rs.internal.mappers.UserMapper;
import org.tkit.quarkus.log.cdi.LogService;
import org.tkit.quarkus.rs.context.token.TokenException;

import gen.org.tkit.onecx.iam.kc.internal.AdminInternalApi;
import gen.org.tkit.onecx.iam.kc.internal.model.ProblemDetailResponseDTO;
import gen.org.tkit.onecx.iam.kc.internal.model.RoleSearchCriteriaDTO;
import gen.org.tkit.onecx.iam.kc.internal.model.UserSearchCriteriaDTO;

@LogService
@ApplicationScoped
public class AdminRestController implements AdminInternalApi {

    @Inject
    KeycloakAdminService adminService;

    @Inject
    UserMapper userMapper;

    @Inject
    RoleMapper roleMapper;

    @Inject
    ExceptionMapper exceptionMapper;

    @Override
    public Response getAllProviders() {
        return Response.status(Response.Status.OK).entity(adminService.getAllKeycloaksAndRealms()).build();
    }

    @Override
    public Response getUserRoles(String provider, String realm, String userId) {
        return Response.ok().entity(roleMapper.map(adminService.getUserRoles(provider, realm, userId))).build();
    }

    @Override
    public Response searchRolesByCriteria(String provider, String realm, RoleSearchCriteriaDTO roleSearchCriteriaDTO) {
        var criteria = roleMapper.map(roleSearchCriteriaDTO);
        var result = adminService.searchRoles(provider, realm, criteria);
        return Response.ok(roleMapper.map(result)).build();
    }

    @Override
    public Response searchUsersByCriteria(String provider, String realm, UserSearchCriteriaDTO userSearchCriteriaDTO) {
        var criteria = userMapper.map(userSearchCriteriaDTO);
        var usersPage = adminService.searchUsers(provider, realm, criteria);
        return Response.ok(userMapper.map(usersPage, realm)).build();
    }

    @ServerExceptionMapper
    public RestResponse<ProblemDetailResponseDTO> constraint(TokenException ex) {
        return exceptionMapper.exception(ex.getKey(), ex.getMessage());
    }

    @ServerExceptionMapper
    public RestResponse<ProblemDetailResponseDTO> constraint(KeycloakException ex) {
        return exceptionMapper.exception(ex);
    }

    @ServerExceptionMapper
    public RestResponse<ProblemDetailResponseDTO> constraint(ConstraintViolationException ex) {
        return exceptionMapper.constraint(ex);
    }
}
