package com.lynas.springoauth2poc

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ClientRegistrations
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import java.util.*


@SpringBootApplication
class SpringOAuth2PocApplication

fun main(args: Array<String>) {
    runApplication<SpringOAuth2PocApplication>(*args)
}


@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
class OAuth2LoginSecurityConfig : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
            .authorizeRequests().antMatchers("/").permitAll()
            .and()
            .authorizeRequests().anyRequest().authenticated()
            .and()
            .oauth2Login {
                it.userInfoEndpoint { u ->
                    u.oidcUserService(oidcUserService())
                }
            }
            .logout {
                it.logoutSuccessHandler(oidcLogoutSuccessHandler())
            }

    }

    @Bean
    fun oidcUserService(): OAuth2UserService<OidcUserRequest, OidcUser> {
        val delegate = OidcUserService()

        return OAuth2UserService { userRequest ->
            var oidcUser = delegate.loadUser(userRequest)
            val accessToken = userRequest.accessToken
            val mappedAuthorities = getRolesFromToken(accessToken.tokenValue)
            oidcUser = DefaultOidcUser(mappedAuthorities, oidcUser.idToken, oidcUser.userInfo)

            oidcUser
        }
    }

    @Bean
    fun clientRegistrationRepository(): ClientRegistrationRepository {
        val clientRegistration = ClientRegistrations
            .fromIssuerLocation("http://localhost:8080/auth/realms/demo")
            .clientId("demo")
            .clientSecret("9bc8a140-187f-43f2-8efb-8b9d6686824f")
            .scope("openid")
            .build()
        return InMemoryClientRegistrationRepository(clientRegistration)
    }


    private fun oidcLogoutSuccessHandler(): LogoutSuccessHandler {
        val oidcLogoutSuccessHandler = OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository())
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}")
        return oidcLogoutSuccessHandler
    }
}

@Controller
class DemoController {

    @GetMapping("/private")
    fun private(
        @RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient,
        @AuthenticationPrincipal oauth2User: OAuth2User
    ): String {
        return "private"
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/private/admin")
    fun privateAdmin(
        @RegisteredOAuth2AuthorizedClient authorizedClient: OAuth2AuthorizedClient,
        @AuthenticationPrincipal oauth2User: OAuth2User
    ): String {
        return "private"
    }

    @GetMapping("/")
    fun public() = "public"

}


fun getRolesFromToken(token: String): HashSet<GrantedAuthority> {
    val chunks = token.split(".");
    val decoder = Base64.getDecoder();
    val payload = String(decoder.decode(chunks[1]))
    val map = ObjectMapper().readValue<MutableMap<String, Any>>(payload)
    println(map.toString())
    val ra = map["resource_access"] as Map<String, Any>
    val ad = ra["demo"] as Map<String, String>
    val roles = ad["roles"] as ArrayList<String>
    return roles.map { SimpleGrantedAuthority(it) }.toHashSet()
}