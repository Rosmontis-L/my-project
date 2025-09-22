package com.example.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtils {

    //JWTToken的加密key，在application里面
    @Value("${spring.security.jwt.key}")
    String key;

    //设置的有效时间
    @Value("${spring.security.jwt.expire}")
    int expire;

    public DecodedJWT resolve(String headerToken) {
        String token = this.convertToken(headerToken);
        if (token == null) return null;
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT verify = verifier.verify(token);
            //解析JWTToken是否被篡改，如果篡改会抛出运行异常
            Date expiresAt = verify.getExpiresAt();
            return new Date().after(expiresAt) ? null : verify;
            //判断现在的日期是否超过设定的过期时间
        } catch (JWTVerificationException e){
            return null;
        }
    }
    //对JWTToken进行解析验证

    public String createJwt(UserDetails details, int id, String username) {
        Algorithm algorithm = Algorithm.HMAC256(key);
        Date expire = expireTime();
        return JWT.create()
                .withClaim("id", id)
                .withClaim("name", username)
                .withClaim("authorities", details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expire)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }
    //创建JWTToken

    public Date expireTime(){
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire * 24);
        return calendar.getTime();
    }
    //计算过期时间返回

    public UserDetails toUser(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        return User
                .withUsername(claims.get("name").asString())
                .password("*****")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }
    //将jwt里面存储的用户信息转换为UserDetails返回

    public Integer toId(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        return claims.get("id").asInt();
    }

    private String convertToken(String headerToken) {
        if(headerToken == null || !headerToken.startsWith("Bearer ")) {
            return null;
        }
        return headerToken.substring(7);
    }
    //判断这个Token是否为空或者没有以Bearer开头,如果符合要求出去开头返回token
}
