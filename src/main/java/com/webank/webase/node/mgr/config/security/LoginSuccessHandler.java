/*
 * Copyright 2014-2021  the original author or authors.
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
package com.webank.webase.node.mgr.config.security;

import com.webank.webase.node.mgr.account.AccountService;
import com.webank.webase.node.mgr.account.entity.TbAccountInfo;
import com.webank.webase.node.mgr.account.token.TokenService;
import com.webank.webase.node.mgr.base.code.ConstantCode;
import com.webank.webase.node.mgr.base.entity.BaseResponse;
import com.webank.webase.node.mgr.tools.JsonTools;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Log4j2
@Component("loginSuccessHandler")
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private AccountService accountService;
    @Autowired
    private TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        log.debug("login success");

        String accountName = authentication.getName();
        //delete old token and save new
        tokenService.deleteToken(null, accountName);
        String token = tokenService.createToken(accountName, 1);
        // access token save db
        if (null != request.getParameter("access_token")){
            try{
                String accessToken = request.getParameter("access_token");
                if (!tokenService.verifyCodeByQH(accessToken)){
                    log.warn("access_token验证失败");
                    //access_token验证失败
                    tokenService.deleteToken(token, null);
                    BaseResponse baseResponse = new BaseResponse(ConstantCode.INVALID_ACCESS_TOKEN);
                    String backStr = JsonTools.toJSONString(baseResponse);
                    response.setContentType("application/json;charset=UTF-8");
                    response.getWriter().write(backStr);
                    return;
                }
                tokenService.updateAccessToken(token, accessToken);
            }catch (Exception e){

                log.warn("access_token_handle_fail:"+e);
                BaseResponse baseResponse = new BaseResponse(ConstantCode.ACCESS_TOKEN_HANDLE_FAIL);
                String backStr = JsonTools.toJSONString(baseResponse);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write(backStr);
                return;
            }

        }else {
            log.warn("access_token为空");
            //access_token为空
            BaseResponse baseResponse = new BaseResponse(ConstantCode.ACCESS_TOKEN_IS_NULL);
            String backStr = JsonTools.toJSONString(baseResponse);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(backStr);
            return;
        }


        // response account info
        TbAccountInfo accountInfo = accountService.queryByAccount(accountName);
        Map<String, Object> rsp = new HashMap<>();
        rsp.put("roleName", accountInfo.getRoleName());
        rsp.put("account", accountName);
        rsp.put("accountStatus", accountInfo.getAccountStatus());
        rsp.put("token", token);

        BaseResponse baseResponse = new BaseResponse(ConstantCode.SUCCESS);
        baseResponse.setData(rsp);

        String backStr = JsonTools.toJSONString(baseResponse);
        log.debug("login backInfo:{}", backStr);

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(backStr);
    }

}
