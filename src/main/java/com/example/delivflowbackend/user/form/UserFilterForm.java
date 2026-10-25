package com.example.delivflowbackend.user.form;

import lombok.Data;

import java.util.UUID;

@Data
public class UserFilterForm {

    // Search by specific fields
    private String emailSearch;
    private String displayNameSearch;
    private String statusSearch;

    // ID range
    private UUID minId;
    private UUID maxId;
}