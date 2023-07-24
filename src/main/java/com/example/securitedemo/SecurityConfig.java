package com.example.securitedemo;

import com.example.securitedemo.secr.entities.AppUser;
import com.example.securitedemo.secr.filters.JwtAuthenticationFilter;
import com.example.securitedemo.secr.filters.JwtAuthorizationFilter;
import com.example.securitedemo.secr.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private AccountService accountService;
    @Override   //specifie quelle sont les users qui ont le droit d'accede
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.userDetailsService(new UserDetailsService() {
           @Override
           public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
               AppUser appUser=accountService.loadUserByUsername(username);
               //Conversion vers collection GrantedAuthority
               Collection<GrantedAuthority>authorities=new ArrayList<>();
               appUser.getAppRoles().forEach(r -> authorities.add(new SimpleGrantedAuthority(r.getRoleName())));

               return new User(appUser.getUserName(),appUser.getPassword(),authorities);
           }
       });


    }


    @Override//specifie les droits d'accée
    protected void configure(HttpSecurity http) throws Exception {
        //http.csrf().disable();   pour auth statful
        http.csrf().disable();           //pour auth statlus parce que il utilise les sessions
        http.authorizeRequests().antMatchers("/h2-console/**","/refreshToken/**","/login/**").permitAll();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//2:13:27
        http.headers().frameOptions().disable(); // desable frames mais selment dans le cas de H2
        //http.authorizeRequests().anyRequest().permitAll();  // toutes les requites ne nécessite pas une identification
        //http.formLogin();
       /*
  http.authorizeRequests().antMatchers(HttpMethod.POST,"/users/**").hasAuthority("ADMIN");  //specifie les ressources que vous allez specifie les ressources que vous allez autoriser
  http.authorizeRequests().antMatchers(HttpMethod.GET,"/users/**").hasAuthority("USER");
*/
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
