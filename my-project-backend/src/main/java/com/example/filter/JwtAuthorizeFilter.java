package com.example.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthorizeFilter extends OncePerRequestFilter {

    @Resource
    JwtUtils utils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        DecodedJWT jwt = utils.resolve(authorization);
        if(jwt != null) {
            UserDetails user = utils.toUser(jwt);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            //Security内部验证，创建一个已经认证的Authentication对象
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            //将http的详细请求添加到认证对象中
            SecurityContextHolder.getContext().setAuthentication(authentication);
            //将的认证对象添加到springSecurity的安全上下文，之后就可以通过SecurityContextHolder获取仍认证对象
            request.setAttribute("id", utils.toId(jwt));
        }//这里也就是通过解析验证之后发现JWTToken没有出现过期或者被篡改的情况下再处理
        filterChain.doFilter(request, response);
    }
}
