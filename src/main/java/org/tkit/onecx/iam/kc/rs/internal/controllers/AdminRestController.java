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
import gen.org.tkit.onecx.iam.kc.internal.model.UserRolesSearchRequestDTO;
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
        return Response.status(Response.Status.OK).entity(adminService.getAllProviderAndDomains()).build();
    }

    @Override
    public Response getUserRoles(String userId, UserRolesSearchRequestDTO userRolesSearchRequestDTO) {
        return Response.ok().entity(roleMapper.map(adminService.getUserRoles(userRolesSearchRequestDTO.getIssuer(), userId)))
                .build();
    }

    @Override
    public Response searchRolesByCriteria(RoleSearchCriteriaDTO roleSearchCriteriaDTO) {
        var criteria = roleMapper.map(roleSearchCriteriaDTO);
        var result = adminService.searchRoles(roleSearchCriteriaDTO.getIssuer(), criteria);
        return Response.ok(roleMapper.map(result)).build();
    }

    @Override
    public Response searchUsersByCriteria(UserSearchCriteriaDTO userSearchCriteriaDTO) {
        var criteria = userMapper.map(userSearchCriteriaDTO);
        var usersPage = adminService.searchUsers(userSearchCriteriaDTO.getIssuer(), criteria);
        return Response.ok(userMapper.map(usersPage, "addRealmHere")).build();
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
