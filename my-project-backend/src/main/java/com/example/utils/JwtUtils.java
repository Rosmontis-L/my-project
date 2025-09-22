package com.example.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtils {

    //JWTToken的加密key，在application里面
    @Value("${spring.security.jwt.key}")
    String key;

    //设置的有效时间
    @Value("${spring.security.jwt.expire}")
    int expire;


    @Resource
    StringRedisTemplate template;

    public boolean invalidateJwt(String headerToken) {
        String token = this.convertToken(headerToken);
        if (token == null) return false;
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT jwt = verifier.verify(token);
            String id = jwt.getId();
            return deleteToken(id, jwt.getExpiresAt());
        }  catch (JWTVerificationException e){
            return false;
        }
    }
    //将要删除的Token存到Redis里面

    private boolean deleteToken(String uuid, Date time) {
        if(this.isInvalidToken(uuid)) return false;
        Date now = new Date();
        long expire = Math.max(time.getTime() - now.getTime(), 0);
        template.opsForValue().set(Const.JWT_BLACK_LIST + uuid, "", expire, TimeUnit.MILLISECONDS);
        return true;
    }
    //先检验redis数据库是否存在这个uuid，存在就不用将这个uuid存入，否则的话存入redis数据库

    private boolean isInvalidToken(String uuid) {
        return Boolean.TRUE.equals(template.hasKey(Const.JWT_BLACK_LIST + uuid));
    }
    //查询redis数据库是否有这个uuid

    public DecodedJWT resolve(String headerToken) {
        String token = this.convertToken(headerToken);
        if (token == null) return null;
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT verify = verifier.verify(token);
            //解析JWTToken是否被篡改，如果篡改会抛出运行异常
            if(this.isInvalidToken(verify.getId()))
                return null;
            //验证这个uuid是否被丢弃了
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
                .withJWTId(UUID.randomUUID().toString())
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
