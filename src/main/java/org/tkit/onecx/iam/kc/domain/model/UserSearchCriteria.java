package org.tkit.onecx.iam.kc.domain.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserSearchCriteria {

    private String userName;

    private String firstName;

    private String lastName;

    private String email;

    private Integer pageNumber = 0;

    private Integer pageSize = 10;
}
