package com.example.delivflowbackend.user.specification;

import com.example.delivflowbackend.user.entity.User;
import com.example.delivflowbackend.user.entity.UserStatus;
import com.example.delivflowbackend.user.form.UserFilterForm;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

public class UserSpecification {

    // build dynamic user filters for admin search
    public static Specification<User> buildWhere(UserFilterForm form) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // search by email (LIKE, case-insensitive)
            if (form.getEmailSearch() != null && !form.getEmailSearch().isEmpty()) {
                String value = "%" + form.getEmailSearch().toLowerCase() + "%";
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("email")), value));
            }

            // search by display name (LIKE, case-insensitive)
            if (form.getDisplayNameSearch() != null && !form.getDisplayNameSearch().isEmpty()) {
                String value = "%" + form.getDisplayNameSearch().toLowerCase() + "%";
                predicates.add(criteriaBuilder.like(criteriaBuilder.lower(root.get("displayName")), value));
            }

            // search by status (exact match on the user_status enum)
            if (form.getStatusSearch() != null && !form.getStatusSearch().isEmpty()) {
                try {
                    predicates.add(criteriaBuilder.equal(
                            root.get("status"), UserStatus.valueOf(form.getStatusSearch().toUpperCase())));
                } catch (IllegalArgumentException ignored) {
                    // invalid status filter value - ignore
                }
            }

            // id range filter
            if (form.getMinId() != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("id"), form.getMinId()));
            }

            if (form.getMaxId() != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("id"), form.getMaxId()));
            }

            // combine all search with AND
            return criteriaBuilder.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }
}