package com.km.config;
/**
 * Created by asus-pc on 2019/6/26.
 */

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @ClassName MySercurityConfig
 * @Description TODO
 * @Author wujiancai
 * @Date 2019/6/26 19:34
 * @Version 1.0
 **/
@EnableWebSecurity
public class MySercurityConfig extends WebSecurityConfigurerAdapter{
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //开启Sercurity的登录页面
        http.formLogin();

        //开启自动注销功能
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能
        http.rememberMe();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*super.configure(auth);*/
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("zhangsan").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP2")
                .and()
                .withUser("lisi").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP2","VIP3")
                .and()
                .withUser("wangwu").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP3");
    }
}
