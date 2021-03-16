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
package node.mgr.test.monitor;

import node.mgr.test.base.TestBase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

public class MonitorControllerTest extends TestBase {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Before
    public void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }


    @Test
    public void testUserList() throws Exception {
        ResultActions resultActions = mockMvc
            .perform(MockMvcRequestBuilders.get("/monitor/userList/1"));
        resultActions.
            andExpect(MockMvcResultMatchers.status().isOk()).
            andDo(MockMvcResultHandlers.print());
        System.out.println(
            "======================response:" + resultActions.andReturn().getResponse()
                .getContentAsString());
    }

    @Test
    public void testInterfaceList() throws Exception {
        ResultActions resultActions = mockMvc
            .perform(MockMvcRequestBuilders.get("/monitor/interfaceList/1?userName=abc"));
        resultActions.
            andExpect(MockMvcResultMatchers.status().isOk()).
            andDo(MockMvcResultHandlers.print());
        System.out.println(
            "======================response:" + resultActions.andReturn().getResponse()
                .getContentAsString());
    }

    @Test
    public void testUnusualUserList() throws Exception {
        ResultActions resultActions = mockMvc
            .perform(MockMvcRequestBuilders.get("/monitor/unusualUserList/1/1/15"));
        resultActions.
            andExpect(MockMvcResultMatchers.status().isOk()).
            andDo(MockMvcResultHandlers.print());
        System.out.println(
            "======================response:" + resultActions.andReturn().getResponse()
                .getContentAsString());
    }

    @Test
    public void testTransList() throws Exception {
        ResultActions resultActions = mockMvc.perform(
            MockMvcRequestBuilders.get("/monitor/transList/1?userName=safas&interfaceName=fasdf"));
        resultActions.
            andExpect(MockMvcResultMatchers.status().isOk()).
            andDo(MockMvcResultHandlers.print());
        System.out.println(
            "======================response:" + resultActions.andReturn().getResponse()
                .getContentAsString());
    }

    @Test
    public void testUnusualContractList() throws Exception {
        ResultActions resultActions = mockMvc
            .perform(MockMvcRequestBuilders.get("/monitor/unusualContractList/1/1/15"));
        resultActions.
            andExpect(MockMvcResultMatchers.status().isOk()).
            andDo(MockMvcResultHandlers.print());
        System.out.println(
            "======================response:" + resultActions.andReturn().getResponse()
                .getContentAsString());
    }


}