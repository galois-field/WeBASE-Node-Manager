
/**
 * Copyright 2014-2021  the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.webank.webase.node.mgr.account;

import com.webank.webase.node.mgr.account.entity.*;
import com.webank.webase.node.mgr.account.token.TokenService;
import com.webank.webase.node.mgr.base.code.ConstantCode;
import com.webank.webase.node.mgr.base.controller.BaseController;
import com.webank.webase.node.mgr.base.entity.BasePageResponse;
import com.webank.webase.node.mgr.base.entity.BaseResponse;
import com.webank.webase.node.mgr.base.enums.SqlSortType;
import com.webank.webase.node.mgr.base.exception.NodeMgrException;
import com.webank.webase.node.mgr.config.properties.ConstantProperties;
import com.webank.webase.node.mgr.tools.JsonTools;
import com.webank.webase.node.mgr.tools.NodeMgrTools;
import com.webank.webase.node.mgr.tools.TokenImgGenerator;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Log4j2
@RestController
@RequestMapping(value = "account")
public class AccountController extends BaseController {

    @Autowired
    private AccountService accountService;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private ConstantProperties constants;

    private static final int PICTURE_CHECK_CODE_CHAR_NUMBER = 4;

    /**
     * get verify code when login
     */
    @GetMapping(value = "pictureCheckCode")
    public BaseResponse getPictureCheckCode() throws Exception {
        Instant startTime = Instant.now();
        log.info("start getPictureCheckCode startTime:{}", startTime);
        // random code
        String checkCode;
        if (constants.getEnableVerificationCode()) {
            checkCode = NodeMgrTools.randomString(PICTURE_CHECK_CODE_CHAR_NUMBER);
        } else {
            checkCode = constants.getVerificationCodeValue();
            log.debug("getPictureCheckCode: already disabled check code, and default value is {}", checkCode);
        }

        String token = tokenService.createToken(checkCode, 2);
        log.info("new checkCode:" + checkCode);

        BaseResponse baseResponse = new BaseResponse(ConstantCode.SUCCESS);
        try {
            // 得到图形验证码并返回给页面
            String base64Image = TokenImgGenerator.getBase64Image(checkCode);
            ImageToken tokenData = new ImageToken();
            tokenData.setToken(token);
            tokenData.setBase64Image(base64Image);
            baseResponse.setData(tokenData);
            log.info("end getPictureCheckCode useTime:{} result:{}",
                Duration.between(startTime, Instant.now()).toMillis(), JsonTools.toJSONString(baseResponse));
            return baseResponse;
        } catch (IOException e) {
            log.error("fail getPictureCheckCode:[]", e);
            throw new NodeMgrException(ConstantCode.CREATE_CHECK_CODE_FAIL);
        }
    }


    /**
     * add account info.
     */
    @PostMapping(value = "/accountInfo")
    @PreAuthorize(ConstantProperties.HAS_ROLE_ADMIN)
    public BaseResponse addAccountInfo(@RequestBody @Valid AccountInfo info, BindingResult result)
        throws NodeMgrException {
        checkBindResult(result);
        BaseResponse baseResponse = new BaseResponse(ConstantCode.SUCCESS);
        Instant startTime = Instant.now();
        log.info("start addAccountInfo. startTime:{}", startTime.toEpochMilli());

        // add account row
        accountService.addAccountRow(info);

        // query row
        TbAccountInfo tbAccount = accountService.queryByAccount(info.getAccount());
        tbAccount.setAccountPwd(null);
        baseResponse.setData(tbAccount);

        log.info("end addAccountInfo useTime:{} result:{}",
            Duration.between(startTime, Instant.now()).toMillis(), JsonTools.toJSONString(baseResponse));
        return baseResponse;
    }

    /**
     * update account info.
     * only admin can request this api
     */
    @PutMapping(value = "/accountInfo")
    @PreAuthorize(ConstantProperties.HAS_ROLE_ADMIN)
    public BaseResponse updateAccountInfo(@RequestBody @Valid AccountInfo info, HttpServletRequest request,
        BindingResult result) throws Exception {
        checkBindResult(result);
        BaseResponse baseResponse = new BaseResponse(ConstantCode.SUCCESS);
        Instant startTime = Instant.now();
        log.info("start updateAccountInfo startTime:{}", startTime.toEpochMilli());

        // current
        String currentAccount = accountService.getCurrentAccount(request);

        // update account row
        accountService.updateAccountRow(currentAccount, info);

        // query row
        TbAccountInfo tbAccount = accountService.queryByAccount(info.getAccount());
        tbAccount.setAccountPwd(null);
        baseResponse.setData(tbAccount);

        log.info("end updateAccountInfo useTime:{} result:{}",
            Duration.between(startTime, Instant.now()).toMillis(),
            JsonTools.toJSONString(baseResponse));
        return baseResponse;
    }

    /**
     * query account list.
     */
    @GetMapping(value = "/accountList/{pageNumber}/{pageSize}")
    @PreAuthorize(ConstantProperties.HAS_ROLE_ADMIN)
    public BasePageResponse queryAccountList(@PathVariable("pageNumber") Integer pageNumber,
        @PathVariable("pageSize") Integer pageSize,
        @RequestParam(value = "account", required = false) String account) throws NodeMgrException {
        BasePageResponse pageResponse = new BasePageResponse(ConstantCode.SUCCESS);
        Instant startTime = Instant.now();
        log.info("start queryAccountList.  startTime:{} pageNumber:{} pageSize:{}",
            startTime.toEpochMilli(), pageNumber, pageSize);

        int count = accountService.countOfAccount(account);
        if (count > 0) {
            Integer start = Optional.ofNullable(pageNumber).map(page -> (page - 1) * pageSize)
                .orElse(0);
            AccountListParam param = new AccountListParam(start, pageSize, account,
                SqlSortType.DESC.getValue());
            List<TbAccountInfo> listOfAccount = accountService.listOfAccount(param);
            listOfAccount.stream().forEach(accountData -> accountData.setAccountPwd(null));
            pageResponse.setData(listOfAccount);
            pageResponse.setTotalCount(count);
        }

        log.info("end queryAccountList useTime:{} result:{}",
            Duration.between(startTime, Instant.now()).toMillis(), JsonTools.toJSONString(pageResponse));
        return pageResponse;
    }

    /**
     * delete contract by id.
     */
    @DeleteMapping(value = "/{account}")
    @PreAuthorize(ConstantProperties.HAS_ROLE_ADMIN)
    public BaseResponse deleteAccount(@PathVariable("account") String account)
        throws NodeMgrException {
        BaseResponse baseResponse = new BaseResponse(ConstantCode.SUCCESS);
        Instant startTime = Instant.now();

        accountService.deleteAccountRow(account);

        log.info("end deleteAccount. useTime:{} result:{}",
            Duration.between(startTime, Instant.now()).toMillis(), JsonTools.toJSONString(baseResponse));
        return baseResponse;
    }

    /**
     * update password.
     */
    @PutMapping(value = "/passwordUpdate")
    public BaseResponse updatePassword(@RequestBody @Valid PasswordInfo info, HttpServletRequest request, 
            BindingResult result) throws Exception {
        checkBindResult(result);
        BaseResponse baseResponse = new BaseResponse(ConstantCode.SUCCESS);
        Instant startTime = Instant.now();

        String targetAccount = accountService.getCurrentAccount(request);

        // update account row
        accountService
            .updatePassword(targetAccount, info.getOldAccountPwd(), info.getNewAccountPwd());

        log.info("end updatePassword useTime:{} result:{}",
            Duration.between(startTime, Instant.now()).toMillis(), JsonTools.toJSONString(baseResponse));
        return baseResponse;
    }
    
}
