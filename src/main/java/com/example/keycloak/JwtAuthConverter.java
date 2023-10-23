package com.example.keycloak;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

        private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        private final String principleAttribute = "preferred_username";

        @Override
        public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
            Collection<GrantedAuthority> authorities = Stream.concat(
                    jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                    extractResourceRoles(jwt).stream()
            ).collect(Collectors.toSet());
            return new JwtAuthenticationToken(
                    jwt,
                    authorities,
                    getPrincipleClaimName(jwt)
            );
        }

        private String getPrincipleClaimName(Jwt jwt) {
            String claimName = JwtClaimNames.SUB;
            if (principleAttribute != null) {
                claimName = principleAttribute;
            }
            return jwt.getClaim(claimName);
        }

        private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
            Map<String, Object> resourceAccess;
            Map<String, Object> resource;
            Map<String, Object> resources;
            Collection<String> resourceRole;

            if (jwt.getClaim("resource_access") == null) {
                return Set.of();
            }

            resourceAccess = jwt.getClaim("resource_access");

            // Extract "mohammed-rest-api" resource roles
            if (resourceAccess.get("mohammed-rest-api") == null) {
                return Set.of();
            }

            resources = (Map<String, Object>) resourceAccess.get("mohammed-rest-api");
            resourceRole = (Collection<String>) resources.get("roles");

            // Extract "lakhal_rest_api" resource roles
            if (resourceAccess.get("lakhal_rest_api") == null) {
                return Set.of();
            }

            resource = (Map<String, Object>) resourceAccess.get("lakhal_rest_api");
            resourceRole.addAll((Collection<String>) resource.get("roles"));

            return resourceRole
                    .stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toSet());
        }
    }
