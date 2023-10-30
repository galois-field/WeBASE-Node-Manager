/**
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
import com.webank.webase.node.mgr.account.entity.AccountInfo;
import com.webank.webase.node.mgr.account.entity.TbAccountInfo;
import com.webank.webase.node.mgr.base.code.ConstantCode;
import com.webank.webase.node.mgr.tools.JsonTools;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * config acccount and role.
 */
@Service
@Log4j2
public class AccountDetailsService implements UserDetailsService {

    @Autowired
    @Lazy
    private AccountService accountService;

    @Override
    public UserDetails loadUserByUsername(String account) throws UsernameNotFoundException {

        log.warn("🐕 account"+account);
        // query account
        TbAccountInfo accountRow = null;
        try {
            accountRow = accountService.queryByAccount(account);
            log.warn("🐕账号找到了吗？"+accountRow);
        }catch (Exception e){
            log.warn("🐕账号找到了吗？"+e);
        }

        try {
            if (null == accountRow) {
                // 注册用户
                AccountInfo accountInfo = new AccountInfo();
                accountInfo.setAccount(account);
                String encodePassword = DigestUtils.sha256Hex(account);
                accountInfo.setAccountPwd(encodePassword);
                accountInfo.setRoleId(100001);
                accountService.addAccountRow(accountInfo);
                accountRow = accountService.queryByAccount(account);
            }
        } catch (Exception e) {
            throw new UsernameNotFoundException(JsonTools.toJSONString(ConstantCode.DB_EXCEPTION));
        }

        log.warn("1🐕");
        // add role
        List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
        list.add(new SimpleGrantedAuthority("ROLE_" + accountRow.getRoleName()));
        User authUser = new User(account, accountRow.getAccountPwd(), list);
        log.warn("1🐕authUser："+authUser.getUsername());
        log.warn("2🐕authUser："+authUser.getPassword());
        log.warn("3🐕authUser："+authUser.getAuthorities().toString());
        return authUser;
    }
}
