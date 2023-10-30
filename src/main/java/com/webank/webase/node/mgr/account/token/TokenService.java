/**
 * Copyright 2014-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.webase.node.mgr.account.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webank.webase.node.mgr.base.code.ConstantCode;
import com.webank.webase.node.mgr.base.enums.TokenType;
import com.webank.webase.node.mgr.base.exception.NodeMgrException;
import com.webank.webase.node.mgr.config.properties.ConstantProperties;
import com.webank.webase.node.mgr.tools.NodeMgrTools;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.core.util.Assert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * token service.
 */
@Log4j2
@Service
public class TokenService {
    @Autowired
    private ConstantProperties properties;
    @Autowired
    private TokenMapper tokenMapper;
    @Autowired
    private ObjectMapper objectMapper;


    /**
     * create token.
     */
    public String createToken(String value, int type) {
        if (StringUtils.isBlank(value)) {
            log.error("fail createToken. param is null");
            return null;
        }
        // support guomi
        String token = NodeMgrTools.shaEncode(UUID.randomUUID() + value);
        //save token
        TbToken tbToken = new TbToken();
        tbToken.setToken(token);
        tbToken.setValue(value);
        tbToken.setAccessToken("");
        if (type == TokenType.USER.getValue()) {
            tbToken.setExpireTime(LocalDateTime.now().plusSeconds(properties.getAuthTokenMaxAge()));
        } else if (type == TokenType.VERIFICATIONCODE.getValue()) {
            tbToken.setExpireTime(LocalDateTime.now().plusSeconds(properties.getVerificationCodeMaxAge()));
        } else {
            log.error("fail createToken. type:{} not support", type);
            return null;
        }
        tokenMapper.add(tbToken);
        return token;
    }


    /**
     * get value from token.
     */
    @SneakyThrows
    public String getValueFromToken(String token) {
        Assert.requireNonEmpty(token, "token is empty");

        //query by token
        TbToken tbToken = tokenMapper.query(token);
        if (Objects.isNull(tbToken)) {
            log.warn("fail getValueFromToken. tbToken is null");
            throw new NodeMgrException(ConstantCode.INVALID_TOKEN);
        }
//        LocalDateTime now = LocalDateTime.now();
//        if (now.isAfter(tbToken.getExpireTime())) {
//            log.warn("fail getValueFromToken. token has expire at:{}", tbToken.getExpireTime());
//            //delete token
//            this.deleteToken(token, null);
//            throw new NodeMgrException(ConstantCode.TOKEN_EXPIRE);
//        }
       if (!verifyCodeByQH(tbToken.getAccessToken())){
           log.warn("fail getValueFromToken. access token external service verification failed:{}", tbToken.getAccessToken());
           //delete token
           this.deleteToken(token, null);
           throw new NodeMgrException(ConstantCode.INVALID_ACCESS_TOKEN);
       }

        return tbToken.getValue();
    }

    /**
     *  verify code by qing hai
     */
    public boolean verifyCodeByQH(String accessToken) throws JsonProcessingException {

        // 请求校验Token地址
        String accessTokenUrl = "http://122.190.56.35:31575/ns-design/oauth2/query_access_token";
        // 拼接请求地址
        String fullUrl = accessTokenUrl + "?access_token=" + accessToken;

        // 处理请求
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(fullUrl, HttpMethod.GET, null, String.class);
        if (response.getStatusCodeValue() == 200){
            String responseBody = response.getBody();
            JsonNode jsonResponse = objectMapper.readTree(responseBody);
            int code = jsonResponse.get("code").asInt();
            if (code == 1){
                return true;
            }
        }else {
            throw new NodeMgrException(ConstantCode.FAILED_TO_GET_QH_TOKEN);
        }

        return false;
    }

    /**
     * update token expire time.
     */
    public void updateExpireTime(String token) {
        Assert.requireNonEmpty(token, "token is empty");
        tokenMapper.update(token, LocalDateTime.now().plusSeconds(properties.getAuthTokenMaxAge()));
    }

    /**
     * delete token.
     */
    public void deleteToken(String token, String value) {
        tokenMapper.delete(token, value);
    }

    /**
     * update token access token
     */
    public void updateAccessToken(String token, String accessToken) {
        Assert.requireNonEmpty(token, "token is empty");
        tokenMapper.updateAccessToken(token, accessToken);
    }
}